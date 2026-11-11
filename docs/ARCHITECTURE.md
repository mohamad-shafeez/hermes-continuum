# Hermes Continuum Architecture

**Revision:** 2026-11-10

**Plugin version:** `0.3.0`

**Schema version:** `3`

**Checkpoint manifest format:** `2`

**Target:** Hermes Agent v0.22.2, commit
`d923a5eb487a17c0a68801bba9ef0f56c81040a8`

## 1. One plugin, nine systems, one spine

Hermes Continuum is one plugin package. It owns one profile-scoped SQLite
database and one append-only Event Spine. All nine systems read and write that
shared history; none has a private database or a separate approval engine.

Hephaestus is a fifth pillar above the original four. It consumes the recorded
history of the other eight systems, forges reviewable artifacts, and enforces
bounded safety leases. It is shown separately here rather than redrawing the
four-pillar topology below.

```
Hermes host
  │  hooks / tools / CLI / slash / dashboard API / Desktop SDK
  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ hermes-continuum                                                    │
│                                                                      │
│  Continuity & Reality      Memory & Evidence                         │
│  ┌───────────┐ ┌────────┐  ┌──────────┐ ┌──────────┐                │
│  │ Continuum │ │ Kairos │  │ Oneiros  │ │ Aletheia │                │
│  └─────┬─────┘ └───┬────┘  └────┬─────┘ └────┬─────┘                │
│        │           │            │            │                       │
│        └───────────┴────────────┴────────────┴──────────┐            │
│                                                         ▼            │
│                                                ┌─────────────────┐   │
│                                                │   Event Spine   │   │
│                                                │ SQLite schema 3 │   │
│                                                └─────────────────┘   │
│                                                         ▲            │
│  Intent & Trust           Foresight & Resilience        │            │
│  ┌────────┐ ┌──────────┐  ┌────────┐ ┌────────┐         │            │
│  │ Telos  │ │ Tripwire │  │ Moirai │ │ Metis  │─────────┘            │
│  └───┬────┘ └────┬─────┘  └───┬────┘ └───┬────┘                      │
│      │           │            │          │                           │
│      └───────────┴────────────┴──────────┘                           │
│                advisory / challenge / policy signals                 │
└──────────────────────────────────────────────────────────────────────┘
```

| System | Pillar | Module | Responsibility |
|---|---|---|---|
| **Continuum** | Continuity & Reality | `continuum_core/checkpoint/`, `spine/`, `service.py` | Event Spine, encrypted checkpoints, resume briefs, Console read model. |
| **Kairos** | Continuity & Reality | `continuum_core/kairos/` | Scoped environment snapshots and reality diffs. |
| **Oneiros** | Memory & Evidence | `continuum_core/oneiros/` | Candidate memory, review, consolidation, recall, re-verification. |
| **Aletheia** | Memory & Evidence | `continuum_core/aletheia/` | Evidence receipts, staling, protected-work challenges. |
| **Telos** | Intent & Trust | `continuum_core/telos/` | User-authored charters, amendments, drift, completion scoring. |
| **Tripwire** | Intent & Trust | `continuum_core/tripwire/` | Deterministic policy and source provenance. |
| **Moirai** | Foresight & Resilience | `continuum_core/moirai/` | Side-effect-free impact previews. |
| **Metis** | Foresight & Resilience | `continuum_core/metis/` | Failure fingerprints and temporary retry circuits. |
| **Hephaestus** | Distillation & Autonomy | `continuum_core/hephaestus/` | Trace distillation, forged skills and automation blueprints, safety leases, Cron enforcement, quarantine. |

## 2. Design invariants

1. **One plugin, one profile database.** The plugin touches only its own SQLite
   database and plugin data directory. Hermes' private session database is never
   opened or modified.
2. **One Event Spine.** New systems append typed events to the same store. There
   is no side-channel history.
3. **One policy and approval path.** Tripwire and the host remain authoritative.
   Aletheia holds, Telos conflicts, Metis preflight, Moirai previews, and
   Hephaestus lease checks can influence the host decision but do not create a
   second approval engine. A lease check can only add a block.
4. **Additive migrations only.** Existing tables and rows are preserved. Schema
   upgrades are ordered, transactional, idempotent, and stamped only after
   success.
5. **Observations are not proof.** Receipts, fingerprints, charters, previews,
   and circuits are scoped records. They do not establish universal truth or
   safety.
6. **External content is untrusted.** Source labels are provenance, not truth.
   Telos charters can be created only from explicit user-authored text.
7. **Fail closed for sensitive enforcement.** A storage or policy failure must
   not silently grant a sensitive action.
8. **Forged artifacts are untrusted and contained.** Trace evidence is
   source-labelled; untrusted text is excluded from the generated procedure.
   Artifact paths must resolve inside the artifact root, writes are atomic and
   checksummed, and forging requires explicit confirmation.
9. **Leases constrain, never authorize.** A safety lease is an additive
   unattended-execution constraint. It never grants host approval, never
   overrides Tripwire, and never turns a denied call into an allowed one.

## 3. Runtime topology

```
__init__.py                 loader entry; registers hooks, tools, CLI, slash
continuum_core/runtime.py   host hook adapter and lazy service lifecycle
continuum_core/service.py   ContinuumService: one composition root
continuum_core/spine/       SQLite schema, store, migrations
continuum_core/checkpoint/  crypto, bundle, resume brief
continuum_core/kairos/      environment snapshots and diffs
continuum_core/aletheia/    receipts, protection, challenges
continuum_core/telos/       charters, drift, completion
continuum_core/moirai/      impact previews
continuum_core/metis/       failures and circuits
continuum_core/hephaestus/  distillation, forged artifacts, leases, quarantine
continuum_core/adapters/    tools, CLI, slash
dashboard/plugin_api.py     FastAPI router at /api/plugins/hermes-continuum
desktop/plugin.js           Hermes Desktop Console
```

`ContinuumService` constructs all system services against the same
`SpineStore`, config, and checkpoint service. Kairos is given a reference to
Aletheia so a reality diff can stale evidence. The checkpoint service is given
Kairos and Telos references for environment snapshots and charter-aware resume
briefs.

## 4. Event Spine v3

### 4.1 Storage and identity

- SQLite in the profile plugin data directory, opened through the host plugin
  data API.
- A stable installation identifier is stored in `meta` and carried in
  checkpoints.
- `PRAGMA user_version` plus `meta.schema_version` record the applied schema.
- A database from a newer release is rejected rather than opened with an
  incomplete schema.

### 4.2 Tables

The schema has 25 plugin-owned tables:

| Group | Tables |
|---|---|
| Core | `meta`, `events`, `sources`, `episodes`, `memory_facts`, `security_decisions`, `checkpoints`, `dream_runs`, `attack_lab_runs`, `resume_briefs` |
| Kairos | `kairos_snapshots`, `kairos_diffs` |
| Aletheia | `aletheia_receipts`, `aletheia_protected`, `aletheia_challenges` |
| Telos | `telos_charters`, `telos_amendments`, `telos_drift`, `telos_completions` |
| Moirai | `moirai_previews` |
| Metis | `metis_failures`, `metis_circuits` |
| Hephaestus | `playbooks`, `safety_leases`, `safety_lease_usage` |

Indexes support timeline/session/source lookups, memory review, security
decisions, checkpoint listing, environment-history queries, evidence status and
artifact lookups, charter state, preview listing, and circuit status.

### 4.3 Migrations

`MIGRATIONS = ((1, SCHEMA_V1), (2, SCHEMA_V2), (3, SCHEMA_V3))`.

- A fresh database applies v1, v2, then v3.
- A v1 database applies v2 and v3; a v2 database applies only v3.
- Each version executes its statements inside one `BEGIN IMMEDIATE`
  transaction. The version stamp is written only after every statement in that
  step succeeds. Any error rolls back the whole upgrade.
- Repeated calls are no-ops.
- V2 adds new tables and adds `verification_state` and `evidence_ref` to
  `memory_facts`. It does not drop or rewrite existing memory rows.
- V3 adds `playbooks`, `safety_leases`, and `safety_lease_usage`, plus
  `attack_lab_runs.suite`. It preserves all v2 rows.

### 4.4 Event vocabulary

There are 67 controlled event types. Legacy systems keep underscore names
(`memory_confirmed`, `checkpoint_imported`, `tool_result_observed`). New systems
use dotted names:

- Kairos: `world.snapshotted`, `reality.diffed`, `precondition.failed`
- Aletheia: `evidence.recorded`, `evidence.confirmed`, `evidence.staled`,
  `evidence.superseded`, `evidence.rejected`, `work.protected`,
  `work.released`, `challenge.detected`, `action.held`, `action.unlocked`
- Telos: `charter.created`, `charter.amended`, `drift.flagged`,
  `subgoal.advanced`, `completion.scored`
- Moirai: `action.previewed`, `action.preview_limited`,
  `action.preview_unsupported`
- Metis: `execution.failure_observed`, `execution.loop_detected`,
  `execution.circuit_opened`, `execution.circuit_closed`,
  `execution.strategy_changed`, `execution.budget_exhausted`
- Oneiros addition: `memory.reverification_required`
- Hephaestus: `playbook.forged`, `skill.forged`, `blueprint.forged`,
  `lease.issued`, `lease.checked`, `lease.violation`, `lease.revoked`,
  `skill.quarantined`, `skill.unquarantined`

The store rejects unknown event types so a typo cannot create an unqueryable
history.

### 4.5 Event integrity and redaction

- Events are append-only. Idempotency keys prevent duplicate observations.
- Details are bounded and passed through deterministic redaction.
- Raw tool results, credentials, transcripts, and large payloads are not stored
  as event details.
- Retention prunes old episodes/sources according to configuration; the
  explicit retention action is confirmation-gated in the CLI and Console.

## 5. System architecture

### 5.1 Continuum

Continuum owns the shared history and portable work state.

- `CheckpointService.export()` creates a new checkpoint identity, asks Kairos
  for a scoped environment snapshot when enabled, snapshots all plugin-owned
  tables, builds an authenticated manifest, encrypts the payload, writes the
  file atomically, and records the checkpoint.
- `inspect()` decrypts and previews without writing.
- `import_checkpoint()` verifies the file checksum, re-imports idempotently,
  preserves conflicting local confirmed values, computes a reality diff when a
  saved fingerprint exists, stales affected evidence, and records a resume
  brief.
- Resume briefs are context, not authorization. They summarize imported state,
  conflicts, environment changes, and the active charter.

### 5.2 Oneiros

- `MemoryService` captures explicit durable statements and corrections as
  candidate facts.
- `ReviewService` confirms, rejects, edits (new version), or forgets with audit
  events.
- `DreamService` consolidates unprocessed episodes deterministically.
- `RecallService` retrieves confirmed and candidate facts; candidates are
  labelled unverified and superseded versions are excluded.
- Verification state is separate from confirmation. An environment change can
  mark a fact for re-verification without rewriting the user's confirmed value.

### 5.3 Tripwire

Tripwire is a deterministic policy evaluator over tool name, arguments,
source context, and trust label.

- `evaluate()` returns `allow`, `approve`, or `block` with a rule key, category,
  reason, and redacted evidence.
- Source classification labels external web/tool results, local file output,
  and terminal commands that fetch remote content.
- Provenance annotation is omitted for `write_file`, `patch`, and
  `skill_manage`; `security-guidance` owns those result transformations.
- The 12-case Attack Lab is a deterministic regression corpus.
- Tripwire is the only policy decision engine. Other systems can add holds,
  previews, or blocks, but the host still handles approval.

### 5.4 Kairos

- `snapshot()` fingerprints a scoped workspace or explicit paths plus system
  facts, selected tool presence, readable Git state, and optional preconditions.
- File contents are not stored. Sensitive filenames/content are skipped, broad
  or remote state is not observed, and file walks/hashing are bounded.
- `diff()` compares a saved fingerprint with a fresh one and records a
  `GREEN`, `AMBER`, or `RED` diff. Changed entries carry severity and messages;
  unobserved state is listed as unverified.
- If the level is not GREEN and a material change exists, Kairos asks Aletheia to
  stale receipts recorded against the saved environment hash.

### 5.5 Aletheia

- `record_receipt()` stores a scoped observation and links it to an environment
  hash/snapshot where available.
- `verify_file()` hashes a local file and compares an expected digest when
  supplied.
- Test receipts require a positive test run; zero-test and failing runs are
  rejected as positive evidence.
- `protect()` creates a protected-artifact record. `challenges_for_action()`
  matches proposed mutations and creates held challenges. Post-tool observation
  resolves them as executed or not executed.
- `release()` ends protection with an audit event. Protection is not
  immutability and does not replace Tripwire/host approval.
- `stale_for_environment()` stales matching receipts and flags linked memory for
  re-verification. It does not erase the user's memory value.
- Unverified accusations are stored as low-confidence candidates, not facts.

### 5.6 Telos

- `ensure_charter()` accepts only `USER_AUTHORED` text. External, imported, or
  tool-generated text cannot create or amend a charter.
- Charters contain a goal, explicit constraints, subgoals, and success criteria.
- `amend()` creates a new version with rationale and audit events.
- `constraint_conflicts()` checks proposed actions against explicit constraints;
  conflicts become approval holds, never silent rewrites.
- `observe_action()` records progress or drift. Drift is advisory and
  heuristic.
- `assess_completion()` scores completion against observed evidence, separates
  verified from partial/unverified work, and excludes prohibited constraints
  from success criteria.

### 5.7 Moirai

- `preview()` classifies a proposed action and returns a deterministic,
  non-executing impact description.
- `VERIFIED PREVIEW` is used only for understood local operations.
- `PARTIAL PREVIEW` is used when the request shape is known but remote or
  row-level effects cannot be established without executing.
- `UNSUPPORTED PREVIEW` is used for arbitrary/complex shell commands and tools
  whose effects cannot be safely predicted.
- Moirai never executes the action, never connects to a remote service, and
  never reads file contents.

### 5.8 Metis

- `observe_result()` fingerprints failed executions by tool, target, normalised
  arguments, and error shape.
- Repeated identical failures without progress open a temporary circuit at the
  configured threshold and window.
- `preflight()` returns an open circuit for matching actions; pre-tool
  enforcement may block when Tripwire has not already blocked.
- Changed arguments are a changed strategy and are not blocked by the same
  circuit.
- `reset_circuit()` requires user confirmation; circuits also expire
  automatically. Circuits are temporary, not permanent denial.

### 5.9 Hephaestus

- `distill()` reads a session's `tool_result_observed` events (bounded by
  configuration), deduplicates retries by
  `(tool_name, json.dumps(params, sort_keys=True))`, and computes
  `confidence = successful_steps / steps_attempted`.
- Each step is classified as verified success, failed anti-pattern, or
  source-labelled untrusted evidence. The generated procedure includes only the
  trusted verified path; failed and untrusted material is rendered separately
  and never interpolated as an instruction.
- `preview_forge()` is side-effect free. `forge()` requires explicit
  confirmation, re-checks confidence, refuses untrusted-only traces and path
  escapes, writes `SKILL.md`, `blueprint.json`, and `manifest.json` atomically
  under the contained artifact root, and records checksums.
- Forged artifacts are registered through `PluginHostRegistrar`, which wraps the
  verified host context. `register_skill(name, path: Path, description="",
  frontmatter=None)` requires an existing `SKILL.md`;
  `register_automation_blueprint(...)` is keyword-only.
- Rehydration is lazy: `ContinuumRuntime.service()` rehydrates once on first
  use, not during registration. Rehydration checks containment, checksums, and
  database quarantine status before re-registering.
- A safety lease scopes allowed tools, lexical path prefixes, domains, opaque
  tools, per-run tool/write/external-call budgets, expiry, an optional
  `cron_job_id`, and a coarse platform/Python environment fingerprint.
- `check_cron_execution()` uses the verified `CronExecution` fields
  (`job_id`, `job_name`, `execution_id`, `source`, `scheduled_instant`,
  `started_at`, `profile`). `current_cron_execution()` does not expose the job
  prompt and returns `None` in delegated child contexts.
- Cron enforcement is additive. A job with no matching forged playbook is
  unscoped and passes through. When a forged playbook matches, a usable active
  lease is required: a matching active lease can allow a scoped call, a
  violation blocks, and a missing, revoked, or expired lease blocks the bound
  job rather than silently unscoping it. An active lease whose playbook is
  quarantined also blocks.
- Lease budgets are per Cron `execution_id`/run, not global. Blocked calls do
  not consume budget.
- Quarantine blocks new leases and Cron checks, updates the artifact manifest,
  and prevents rehydration. It cannot force immediate unregistration from an
  already-loaded host skill registry.
- The skill-write quarantine path blocks generic writes to skill directories
  when session source context is untrusted.

## 6. Runtime lifecycle

### 6.1 `pre_tool_call`

1. Resolve session/task/turn/tool-call identifiers.
2. Find the latest source in the trust window. If any earlier external source
   is still inside the window, enforcement context stays untrusted even when the
   newest source is local.
3. Run Tripwire. Audit non-allow decisions and configured allowed sensitive
   decisions.
4. Run Metis preflight. It can return a block only when Tripwire did not already
   block.
5. Return a Tripwire block immediately, if present.
6. Ask Aletheia for protected-work challenges matching the proposed action.
7. Ask Telos for explicit-constraint conflicts.
8. Produce a Moirai preview for a Tripwire approval or a sensitive action.
9. Run Hephaestus Cron lease enforcement when `current_cron_execution()` is
   present. A lease violation adds a block; a matching allow never removes the
   Tripwire decision or grants approval. The skill-write quarantine path can
   also add a block for untrusted-context skill writes.
10. If any holds exist, return one host `approve` decision with the combined
    reasons and preview. Otherwise return the Tripwire decision (with preview
    appended when applicable).
11. On storage/lookup failure, fall back to static Tripwire evaluation. If even
    that fails, block. If the audit store is unavailable and a sensitive sink is
    proposed, require approval rather than silently allowing it.

This is one decision path. Aletheia/Telos holds do not approve or execute
anything themselves.

### 6.2 `post_tool_call`

Observer-only, best-effort:

1. Classify/record the source and append a `tool_result_observed` event with a
   redacted preview hash and bounded argument preview.
2. Record the result for Metis, which may open a circuit.
3. Resolve Aletheia challenges for the action using the tool status.
4. Update Telos charter progress/drift. The same observation is available to
   Hephaestus distillation, but no artifact is forged automatically.

Observer failures never change the host's tool result.

### 6.3 `transform_tool_result`

Adds an additive provenance label to supported external tool results. It never
touches `write_file`, `patch`, `skill_manage`, Continuum tools, or non-external
tools.

### 6.4 `pre_llm_call`

Builds one context string, capped at 6000 characters:

- Telos charter context, with a Metis circuit note when a circuit is open;
- Oneiros recall context.

### 6.5 Session and approval hooks

Session start/end/finalize/reset and pre/post approval events are append-only
observations. `on_session_finalize` return-message behaviour is not used. Approval
hooks never simulate or decide an approval.

## 7. Cross-system flows

### 7.1 Checkpoint export and import

```
export:
  new checkpoint id
    -> Kairos.snapshot (optional)
    -> SpineStore.export_snapshot (all plugin-owned tables)
    -> manifest v2 + payload schema 1
    -> encrypt (envelope 1)
    -> atomic .hcc write
    -> checkpoint record + events

import:
  checksum -> decrypt -> validate manifest/payload identity
    -> preview without writes
    -> idempotency/conflict preparation
    -> SpineStore.import_snapshot
    -> Kairos.diff(saved fingerprint, current)
    -> Aletheia stale matching receipts + mark memory for re-verification
    -> resume brief + checkpoint record
    -> no external replay
```

A different source installation identifier produces AMBER even if the files
look identical. That is an identity change, not a checksum failure.

### 7.2 Evidence and protection

```
record receipt -> optional environment hash
protect artifact -> protected row
propose matching mutation -> challenge + approval hold
user approves -> host executes
post-tool -> resolve challenge as executed/not executed
environment change -> stale receipt + memory re-verification
```

The challenge layer is deliberately not an undeletable lock.

### 7.3 Execution resilience

```
failed tool result -> Metis fingerprint
repeat threshold -> temporary circuit
next matching preflight -> block (if Tripwire has not blocked)
changed args -> different fingerprint, not blocked
user reset or expiry -> circuit closed
```

### 7.4 Forging and safety leases

```
observed trace
  -> distill (dedupe retries, classify trusted/failed/untrusted)
  -> preview (no writes)
  -> explicit confirmation
  -> re-check confidence, trust, and path containment
  -> atomic SKILL.md + blueprint.json + manifest.json
  -> register through PluginHostRegistrar
  -> optional lease issue (explicit confirmation)

Cron run -> current_cron_execution()
  -> find active lease bound to job_id
  -> check expiry, environment fingerprint, tool/path/domain, budgets
  -> allow scoped call or add block
  -> record lease.checked or lease.violation
  -> Tripwire and host approval remain authoritative
```

Quarantine is a separate state transition: it blocks new leases and Cron
checks, updates the manifest, and prevents rehydration. It does not rewrite an
already-loaded host registry, so immediate unregistration is not claimed.

## 8. Checkpoint format and compatibility

| Layer | Version | Notes |
|---|---|---|
| Encrypted file envelope | `1` | scrypt + AES-256-GCM; authenticated manifest as additional data. |
| Checkpoint manifest | `2` | Adds environment fingerprint/error, schema/policy versions, truncated/available counts, new tables. |
| Payload schema | `1` | Additive. 0.1.0 payload-schema-1 bundles remain importable, including bundles without Hephaestus tables. |

The format-2 manifest includes:

- checkpoint id, created time, source installation id;
- plugin version, schema version, policy version;
- counts and available/truncated table data;
- environment fingerprint hash/fingerprint or environment error;
- excluded categories and a no-replay note.

Import rejects unsupported future payload schemas, wrong passphrases, tampered
ciphertext/manifest, checksum mismatches, oversized files, and identity
disagreement between payload and manifest. It never restores credentials, raw
results, transcripts, Hermes sessions, in-flight state, or external effects.

## 9. Console and API

The backend is a FastAPI router mounted at
`/api/plugins/hermes-continuum/`. The production audit counts 42 routes:

- read: health, status, overview, timeline, event detail, memory, security,
  checkpoints, pillars, reality, evidence, charters, previews, execution,
  playbooks, forge preview, leases;
- actions: memory confirm/reject/edit/forget, dream, retention, suite-aware
  Attack Lab, checkpoint export/inspect/import, resume dismissal, reality
  snapshot/diff, evidence record/confirm/protect/release, charter
  amend/complete, preview creation, circuit reset, forge, playbook
  quarantine/unquarantine, lease issue/revoke.

The Desktop Console has six views: Overview, Nine Systems, Forge, Timeline,
Memory, and Security & Checkpoints. It also has a compact pane, status-bar
counter, palette command, and keybind. It uses Hermes Desktop theme variables
and calls only the plugin's own API.

The Console never receives checkpoint passphrases in tool arguments. Dashboard
checkpoint export is restricted to the plugin checkpoint directory.

## 10. Configuration and failure modes

- All config values are clamped to documented bounds.
- Six system enable flags default to true: Kairos, Aletheia, Telos, Moirai,
  Metis, and Hephaestus. Disabling one removes its observation/action surface;
  Tripwire remains the policy engine. The manifest exposes 32 config keys.
- Trigger-evaluation hooks for Metis, Aletheia, Telos, Moirai, and Hephaestus
  are wrapped so an internal failure is logged and does not silently change
  Tripwire's decision.
- Sensitive enforcement fails closed when storage/policy cannot be trusted.
- Checkpoint crypto failure fails closed; there is no plaintext fallback.
- No general plugin scheduling API: dream and retention are manual/explicit
  actions. Hephaestus observes a Cron execution only when the host supplies
  `current_cron_execution()`.

## 11. Test architecture

The formal suite is offline and uses temporary profile databases and a recording
host context. It has 181 tests across 18 files, including:

- migration, store, isolation, manifest, and installation contracts;
- runtime hook ordering and fail-closed behaviour;
- policy cases and the 12-case Tripwire Attack Lab;
- memory, checkpoint crypto/import, dashboard, tools/CLI;
- focused Kairos, Aletheia, Telos, Moirai, Metis, and Hephaestus suites;
- the 4-case Hephaestus Attack Lab, lease enforcement, and skill-write
  quarantine;
- eight-system integration, Hephaestus service/dashboard integration, and
  old-bundle compatibility.

This architecture is not live acceptance. Static validation, doctor
registration, Node syntax, and backend tests do not prove that a new profile can
enable the plugin or that the production Desktop renders the Console for this
build.

## 12. Compatibility and extension rules

1. Keep one profile database and one Event Spine.
2. Keep Tripwire as the only policy engine; add advisory/hold/constraint
   signals, not a second approval engine. Leases may add blocks only.
3. Add new event types to the controlled vocabulary; use dotted names for new
   systems and keep legacy names stable.
4. Extend checkpoints additively; preserve envelope/payload compatibility unless
   a documented breaking version is authorized.
5. Keep migrations ordered, transactional, idempotent, and non-destructive.
6. Keep new systems general-purpose across research, documents, files, shells,
   APIs, messaging, databases, and software work.
7. Keep forged artifacts inside the plugin artifact root and re-check
   containment and checksums during rehydration.
8. Keep lease checks additive and per-run; never let them grant approval.
9. Do not claim TOCTOU immunity, rollback, arbitrary shell simulation, universal
   evidence, immutable protection, guaranteed loop prevention, or guaranteed
   safety.

## 13. Known architectural limits

- Kairos observes scoped state only. It cannot see remote services, process
  memory, broad system state, or changes after a hash is taken.
- Aletheia receipts establish only what was observed in scope. They do not prove
  factual correctness or future stability.
- Aletheia protection is a challenge layer, not immutability.
- Telos drift is advisory and heuristic; charter creation is limited to explicit
  user-authored text.
- Moirai labels unsupported/complex actions rather than simulating them.
- Metis fingerprints are heuristic and circuits are temporary; not every loop is
  detected.
- Checkpoints restore plugin-owned records only.
- The new systems, including Hephaestus, lack live production-session
  acceptance for 0.3.0.
- A live new-profile `plugins enable`, production Desktop launch, real Cron
  execution, and production skill/blueprint rehydration remain unverified.
- Hephaestus leases are lexical and coarse-grained, not a kernel sandbox or a
  TOCTOU guarantee. Quarantine does not force immediate unregistration from an
  already-loaded host registry.
- A forged skill can still be wrong. Review is required before reuse.
