# Changelog

All notable changes to Hermes Continuum are documented here.

## 0.3.0 - 2026-11-10

Nine-system implementation release. Hephaestus is added inside the existing
plugin, profile database, Event Spine, and Console. All eight prior systems and
their public surfaces are preserved.

### Added

- **Event Spine v3:** additive, transactional, idempotent migration from schema
  v2 to v3. A fresh install applies v1, v2, then v3. Existing v2 data migrates
  in place; a database from a newer schema is still rejected.
- **Hephaestus:** deterministic trace distillation from observed successful and
  failed steps, with confidence `successful_steps / steps_attempted` and
  retry deduplication by `(tool_name, sorted JSON params)`.
- **Forged artifacts:** contained, checksummed `SKILL.md`, `blueprint.json`, and
  `manifest.json` written atomically under the plugin artifact root. Skills and
  automation blueprints are registered through the verified Hermes
  `PluginHostRegistrar` surface.
- **Safety leases:** bounded allowed tools, lexical path prefixes, domains,
  opaque-tool policy, per-run tool/write/external-call budgets, expiry, optional
  Cron job binding, and a coarse platform/Python environment fingerprint.
- **Unattended Cron enforcement:** `current_cron_execution()` drives additive
  lease checks. A violation blocks; a matching lease never grants approval or
  overrides Tripwire.
- **Quarantine:** playbook quarantine blocks new leases and Cron checks, updates
  the artifact manifest, and prevents rehydration. Generic skill-directory
  writes are quarantined when session source context is untrusted.
- **Attack Lab:** a separate deterministic 4-case Hephaestus suite covering
  poisoned source, path escape, lease budget, and environment drift. The
  existing Tripwire suite remains exactly 12 cases.
- Nine new Event Spine types: `playbook.forged`, `skill.forged`,
  `blueprint.forged`, `lease.issued`, `lease.checked`, `lease.violation`,
  `lease.revoked`, `skill.quarantined`, and `skill.unquarantined` (67 total).
- Two new model-facing tools: `continuum_forge` and `continuum_lease` (12 total).
- CLI paths `playbook`, `forge`, `lease`, `attack-lab --suite hephaestus`, and a
  preview-first `/forge` slash command.
- Console/API routes for forge preview/run, playbooks, quarantine/unquarantine,
  lease issue/revoke, and suite-aware Attack Lab runs (42 routes total).
- Desktop Forge view with forge preview/confirmation, artifact review,
  quarantine/release, lease management, and the 4-case Hephaestus lab (six views
  total).
- Eight new Hephaestus keys plus `enable_hephaestus` (32 total).
- `tests/test_hephaestus.py`: 8 focused tests covering distillation, forging,
  refusal paths, lease enforcement, quarantine, and checkpoint round-trips.
- `FINAL_NINE_SYSTEM_IMPLEMENTATION_REPORT.md` with per-system classifications
  and explicit live-verification gaps.

### Changed

- Plugin version is `0.3.0`; schema version is `3`.
- `ContinuumService` composes Hephaestus, exposes the fifth `forge` pillar, and
  supports suite-aware Attack Lab runs while preserving the Tripwire default.
- Checkpoints still use manifest format 2 and payload schema 1. The new tables
  are additive; bundles created before v3 still import without them.
- Desktop and API surfaces now describe nine systems; the Timeline has module
  tabs for all nine.

### Fixed

- Revoked or expired leases still identify their bound Cron job and block that
  job rather than silently unscoping it.
- Active leases are blocked when their playbook is quarantined.
- Model-tool validation failures return `invalid_request` or `forge_refused`
  instead of a generic `internal_error`.
- Playbook summaries expose `cron_job_id`, so lease review can trace Cron
  bindings.

### Security

- Hephaestus is not a second approval engine. Tripwire and the host remain
  authoritative; lease checks only add blocks.
- Forge confirmation is explicit; a preview is the default for the CLI and
  `/forge` slash command.
- Untrusted trace evidence is quarantined from the generated procedure and is
  never interpolated as an instruction.
- Quarantine blocks new leases and Cron checks, but does not claim immediate
  unregistration from an already-loaded host skill registry.
- No TOCTOU immunity, rollback, arbitrary shell simulation, universal evidence,
  immutable protection, guaranteed loop prevention, or live Cron/Desktop
  verification is claimed.

### Verification

- Offline suite: **181 passed, 1 third-party Starlette/httpx deprecation
  warning, 145.94s** via `python -m pytest tests -q`.
- Hermes validator and doctor pass; static registration reports 12 tools and 11
  hooks.
- Node ES-module syntax check, `compileall`, and dashboard route checks pass.
- Live new-profile enable, production Desktop launch, real Cron execution, and
  live nine-system acceptance were not performed.

## 0.2.0 - 2026-11-10

Eight-system implementation release. All five planned systems are implemented
inside the existing plugin, profile database, Event Spine, and Console. The first
three systems and the 0.1.0 public surfaces are preserved.

### Added

- **Event Spine v2:** additive schema migration from v1 to v2, fresh-install
  safety, 22 tables, 58 controlled event types, dotted names for the new systems,
  and 23 manifest configuration keys.
- **Kairos:** scoped environment snapshots, optional preconditions and required
  tools, GREEN/AMBER/RED reality diffs, checkpoint fingerprints, and evidence
  staling after material change.
- **Aletheia:** file, test, command, and custom evidence receipts; current/stale/
  superseded/rejected states; protected-work challenge holds; release and
  accusation handling; evidence-aware Oneiros re-verification.
- **Telos:** user-authored charters, versioned amendments, constraint-conflict
  holds, advisory drift detection, subgoal advancement, and evidence-linked
  completion scoring.
- **Moirai:** deterministic, side-effect-free impact previews with explicit
  VERIFIED, PARTIAL, and UNSUPPORTED levels. It never executes a proposal.
- **Metis:** failure fingerprints, repeated-failure circuits, preflight blocking,
  alternatives, user reset, and automatic expiry.
- **Checkpoint format 2:** manifest v2 with environment fingerprints and all new
  tables, import-time reality diff, stale-evidence handling, and extended resume
  briefs. The encrypted file envelope remains format 1 and payload schema 1;
  0.1.0 bundles remain importable.
- Five new model-facing tools: `continuum_reality`, `continuum_evidence`,
  `continuum_charter`, `continuum_preview`, and `continuum_execution` (10 total).
- CLI inspection/action paths for reality, evidence, charter, preview, and
  execution; restored `recall`, `resume show`, `resume dismiss`, and
  confirmation-gated `retention --yes` compatibility paths. The 0.1.0
  `memory edit --value` and `checkpoint import --confirm` spellings remain
  accepted as aliases.
- Dashboard/API v2 routes for pillars, reality, evidence, charters, previews, and
  execution (35 routes total), plus Desktop Eight Systems pillar cards, module
  tabs, and a non-executing preview form.
- Eight-system integration suite, five focused new-system suites, migration
  coverage, and extended tools/CLI and dashboard tests. Final offline result:
  **172 passed, 1 third-party Starlette/httpx deprecation warning, 138.05s**.
- `FINAL_EIGHT_SYSTEM_IMPLEMENTATION_REPORT.md` with per-system capability
  classifications and explicit exclusions from live verification.

### Changed

- Continuum now composes Continuum, Kairos, Oneiros, Aletheia, Telos, Tripwire,
  Moirai, and Metis through one `ContinuumService`.
- Runtime pre-tool enforcement composes Tripwire, Metis preflight, Aletheia
  protected-work holds, Telos constraint holds, and Moirai previews without
  adding a second approval engine.
- Post-tool observation resolves Aletheia challenges, records Metis failures, and
  updates Telos progress/drift. Pre-LLM context combines Telos charter and
  Metis circuit state with Oneiros recall.
- README, implementation status, technical verification, architecture, and
  security documentation describe all eight systems and the v2 formats.

### Fixed

- Aletheia no longer creates duplicate held challenges for the same action.
- Protected-artifact matching handles Windows-style JSON paths.
- Metis captures failure details, normalises error categories, and redacts
  secrets in fingerprints.
- Moirai classifies read-only, shell, and file actions correctly and records
  accurate action references.
- Telos rejects external text as a charter source and excludes prohibited
  constraints from success criteria.
- Kairos snapshots/diffs and `continuum_reality` accept optional preconditions.

### Security

- Tripwire remains the only policy engine. Aletheia and Telos holds are approval
  triggers handled by the host; Metis can only block when Tripwire has not
  already blocked.
- Evidence confirmation/protection/release, charter amendment/completion, and
  execution reset are explicit user-confirmed, Tripwire-gated mutations.
- Aletheia protection is documented as a challenge layer, not immutability.
- Telos charters cannot be created or amended by external content.
- Moirai previews are non-executing and explicitly partial/unsupported where
  effects cannot be established.
- Metis circuits are temporary and user-resettable; they are not permanent
  denial or a guarantee against all loops.

### Verification limits

- The five new systems are covered by offline unit and integration tests, not a
  live production Hermes session.
- Static validation and doctor registration pass (10 tools, 11 hooks), but a
  live new-profile `plugins enable` and production Desktop launch remain
  unverified for this exact build.
- No TOCTOU immunity, rollback, arbitrary shell simulation, universal evidence,
  guaranteed loop prevention, guaranteed safety, Git repository, publication,
  catalog entry, or hackathon submission is claimed or included.

## Pre-0.2.0 — repository audit and expansion preparation

### Changed

- Quarantined the generated `pdf_extracted.txt` duplicate outside the plugin;
  the original PDF remains the authoritative formatted first-three blueprint.
- Moved the historical Phase 0 test harnesses byte-for-byte to an external
  sibling evidence archive because their private-core imports caused a plugin
  validator warning. Historical results and screenshots remain in the plugin.
- Moved the superseded three-system markdown blueprint to `docs/history/` and
  marked it as historical; the eight-system expansion blueprint remains the
  original design reference.
- Added `.gitignore` for Python caches, virtual environments, local Hermes
  profiles, checkpoint bundles, logs, secrets, and editor/OS files while
  keeping `dashboard/dist/index.js`, tests, fixtures, documentation, and
  intended evidence tracked.
- Added repository audit, cleanup manifest, expansion-readiness, and regression
  documentation. This cleanup preceded implementation of the five new systems.

## 0.1.0 — 2026-11-09

Initial integrated MVP for Hermes Agent v0.22.2.

### Added

- Unified plugin package: `plugin.yaml`, root `__init__.py`, `continuum_core/`,
  hidden dashboard backend, and Hermes Desktop Console.
- Append-only Event Spine with profile-scoped SQLite storage, versioned schema,
  idempotent events, bounded details, redaction, retention, and snapshot export.
- Tripwire deterministic policy: credential-exfiltration blocks; approval for
  destructive, remote-execution, persistence, credential-read, protected-path,
  external-side-effect, untrusted-context, and plugin-state-change actions.
- Source classification and provenance labels, with explicit non-competition on
  `write_file`, `patch`, and `skill_manage`.
- 12-case Attack Lab fixture and deterministic runner.
- Oneiros memory candidates, review, versioning, contradiction links,
  per-preference keys, cross-episode dedupe, dream consolidation, and recall.
- Continuum encrypted checkpoints using scrypt + AES-256-GCM, authenticated
  preview/import, conflict handling, idempotent re-import, and resume briefs.
- Five model-facing tools and the `hermes continuum` CLI plus `/continuum` slash
  command.
- Continuum Console Desktop views: Overview, Timeline, Memory, Security &
  Checkpoints, compact pane, status-bar chip, and palette command.
- Security & Checkpoints retention panel backed by the real `/retention`
  endpoint.
- Dashboard API endpoints for status, timeline, memory review, security,
  Attack Lab, retention, checkpoints, and resume briefs.
- Formal offline test suite covering storage, policy, memory, checkpoints,
  runtime hooks, tools/CLI, dashboard, Console route parity, isolation, and
  installation loading. Final result: 125 passed.
- Architecture, security, README, implementation-status, technical
  verification, and final implementation report documentation.

### Security

- Model-facing memory mutations and checkpoint export/import require explicit
  host approval via Tripwire `tripwire.plugin.state_change`.
- Dashboard checkpoint export rejects arbitrary destination paths and writes
  only to the plugin checkpoint directory.
- Checkpoint passphrases are never accepted in model-visible tool arguments.
- Storage/policy failures fail closed for sensitive sinks.
- Later local tool output cannot mask an earlier untrusted external source in
  the enforcement window.
- Terminal commands containing network verbs are treated as external sources.

### Known limitations

- No general plugin cron API; dream runs are manual.
- Local-directory plugin install is rejected by Hermes; use the profile copy
  workflow.
- Terminal classification is heuristic.
- Checkpoints do not migrate live sessions, processes, GUI state, or Hermes'
  private session database.
- Catalog publication is not included in this release.
