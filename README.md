# Hermes Continuum

Hermes Continuum is one integrated plugin for the **Hermes Agent**, a
general-purpose autonomous action agent. Hermes is not limited to coding: it
works with research and browsing, documents and spreadsheets, files, shells and
commands, APIs, messaging, databases, and software development. Continuum is
built for that wider world.

Version **0.3.0** implements all nine cooperating systems on one append-only
**Event Spine**, with one profile database and one Console:

| # | System | Plain-English role |
|---|---|---|
| 1 | **Continuum** | Portable work state: Event Spine, encrypted checkpoints, resume briefs, and the Console read model. |
| 2 | **Oneiros** | Reviewed memory: candidates, explicit confirmation, corrections, dream consolidation, and recall. |
| 3 | **Tripwire** | Deterministic security policy and source provenance. It is the only policy engine; the host remains the approval authority. |
| 4 | **Kairos** | Environmental reality: scoped workspace fingerprints, checkpoint snapshots, and GREEN/AMBER/RED diffs. |
| 5 | **Aletheia** | Evidence receipts and protected-work challenges. Receipts describe observations; they do not prove truth. |
| 6 | **Telos** | Goal integrity: user-authored charters, explicit amendments, drift advisories, and honest completion scoring. |
| 7 | **Moirai** | Side-effect-free impact previews for proposed actions. It never executes the action. |
| 8 | **Metis** | Execution resilience: failure fingerprints and temporary retry circuits that interrupt recognised unproductive loops. |
| 9 | **Hephaestus** | Trace distillation: reviewable skills and automation blueprints forged from successful traces, bounded by explicit safety leases. |

The five product pillars are **Continuity & Reality**, **Memory & Evidence**,
**Intent & Trust**, **Foresight & Resilience**, and **Distillation & Autonomy**.
The first four pillars combine two systems each on the shared spine; Hephaestus
composes the other eight systems' history into reusable, reviewable artifacts.

> **Current release:** `0.3.0`
>
> **Implemented systems:** Continuum, Oneiros, Tripwire, Kairos, Aletheia, Telos,
> Moirai, Metis, Hephaestus
>
> **Schema:** `3`
>
> **Checkpoint manifest format:** `2` (encrypted file envelope `1`, payload
> schema `1`)
>
> **Target runtime:** Hermes Agent **v0.22.2**, commit
> `d923a5eb487a17c0a68801bba9ef0f56c81040a8`
>
> **Registration:** 12 tools, 11 hooks, 42 Console/API routes, 67 event types,
> 25 tables, 32 manifest configuration keys
>
> **Publication:** local submission preparation only. No remote, push, PR,
> catalog entry, release, or hackathon submission has been created.

## Submission verification at a glance

The isolated `continuum-live` profile on Hermes Agent `v0.22.2` loaded this
plugin and reported 12 tools and 11 hooks. A fresh host-mediated
`continuum_status` call produced `continuum_status ok in 81 ms` in the Event
Spine, and the production Hermes Desktop Console rendered the live profile,
including the Timeline event and an encrypted checkpoint created through the
Dashboard API. The tested model was a local deterministic OpenAI-compatible
fixture, not a production model; the host tool registry, plugin, Event Spine,
and Desktop were real. A normal one-click Desktop launch was blocked by the
host's interrupted source update, so the Desktop proof used a manually started
isolated backend and the production Electron app. The host update marker was
not modified. See [VERIFICATION.md](VERIFICATION.md) for exact commands,
outputs, screenshots, and the boundary between live and offline evidence.

## What the integrated product does

- **What happened?** The Event Spine records sessions, tool calls, source
  provenance, security decisions, memory changes, checkpoints, environment
  diffs, evidence receipts, charter events, previews, and retry circuits.
- **What is true right now?** Kairos compares the current scoped environment
  with a saved fingerprint and reports GREEN, AMBER, or RED. Unobserved state is
  reported as unverified, not guessed.
- **What is safe?** Tripwire blocks high-confidence credential exfiltration,
  asks the user about sensitive, destructive, or ambiguous actions, and records
  the decision. A model cannot grant itself permission.
- **What is remembered, and how firmly?** Oneiros proposes candidate facts; only
  explicit review promotes a candidate to confirmed memory. Aletheia receipts
  can support or stale a fact, but do not make it universally true.
- **What did the user actually ask for?** Telos builds a charter only from
  explicit user-authored text, tracks amendments, flags conflicts with stated
  constraints, and scores completion from observed evidence.
- **What would this action touch?** Moirai produces a deterministic,
  non-executing preview where the request shape is understood. Unsupported
  effects are labelled as unsupported.
- **Why is this operation repeating?** Metis fingerprints repeated failures and
  opens a temporary circuit until the strategy changes or the user resets it.
- **What can safely be reused?** Hephaestus distils successful source-labelled
  traces into a reviewable SKILL.md, an automation blueprint, and a bounded
  safety lease. A forge requires explicit confirmation; a lease never grants
  approval, and quarantined playbooks cannot receive new leases.

A checkpoint now carries more than events and memory: it snapshots the
plugin-owned v3 tables, records an environment fingerprint when Kairos is
available, and on import compares the saved environment with the current one.
If the environment changed, affected Aletheia evidence is marked stale and the
resume brief explains what changed. A checkpoint from another installation is
reported as AMBER because its installation identity differs; that is expected
and is not an error. Nothing external is replayed on import.

## What is implemented in v0.3.0

### Event Spine v3

- Profile-scoped SQLite via `plugin_db()` / `plugin_data_dir()`.
- One additive schema with ordered, transactional, idempotent migrations from
  v1 to v2 to v3 and a fresh-install path that applies v1, v2, then v3.
- 25 tables. The 22 v2 tables are preserved; v3 adds `playbooks`,
  `safety_leases`, and `safety_lease_usage`, plus `attack_lab_runs.suite`.
- 67 controlled event types: legacy systems keep underscore names, newer
  systems use dotted names (`world.snapshotted`, `evidence.recorded`,
  `charter.created`, `action.previewed`, `execution.circuit_opened`,
  `playbook.forged`, and others).
- Append-only events with idempotency keys, bounded details, deterministic
  redaction, retention, and snapshot export/import.
- Stable installation identity and a schema-version stamp. A database from a
  newer release is rejected rather than silently opened incomplete.

### Continuum checkpoints and resume

- Checkpoint manifest format `2`; the encrypted file envelope remains format
  `1`, and the payload schema remains `1` for compatibility with 0.1.0
  bundles. New tables and environment fields are additive. Older bundles
  without `playbooks`, `safety_leases`, or `safety_lease_usage` still import.
- Export/import of all plugin-owned tables. Excluded categories remain
  credentials, raw tool results, transcripts, Hermes private sessions,
  in-flight actions, and external side effects.
- AES-256-GCM encryption with scrypt key derivation
  (`n=2**14, r=8, p=1`), authenticated manifest and payload, size limits, and
  atomic writes.
- Wrong passphrase, tampering, checksum mismatch, or an unsupported future
  schema is rejected. Re-import is idempotent; conflicting local confirmed
  values are preserved and the imported value is proposed as a candidate.
- Import produces a reality diff, stales affected evidence, and writes a
  human-readable resume brief with explicit "context, not authorization"
  language.
- Passphrases never appear in model-visible tool arguments or logs. Use
  `HERMES_CONTINUUM_PASSPHRASE`, CLI `getpass`/`--passphrase-stdin`, or the
  Console HTTP body.

### Oneiros

- Conservative extraction of explicit statements, preferences, corrections,
  and notes from user messages.
- Per-subject preference keys, candidate review, versioned edits, contradiction
  links, and supersession instead of silent deletion.
- Evidence-aware re-verification: import-time environment changes can stale
  evidence and mark the linked memory for re-verification without rewriting the
  user's confirmed value.
- Dream consolidation over unprocessed episodes; idempotent when there is no
  new work.
- Recall prefers confirmed facts, labels candidates as unverified, and excludes
  superseded versions.

### Tripwire

- Deterministic local policy; no LLM decides permission.
- **Block:** high-confidence credential-to-network exfiltration.
- **Approve:** destructive broad operations, remote script execution,
  persistence, credential-file reads, protected-path writes, external side
  effects, sensitive actions in an untrusted context, and model-facing
  Continuum state changes.
- **Allow:** ordinary reads and non-sensitive local actions.
- Source classification for external web/tool results, local file/tool output,
  and terminal commands that fetch remote content.
- Provenance labels on external tool results, added additively where possible.
  `write_file`, `patch`, and `skill_manage` are never transformed here;
  `security-guidance` remains authoritative for those results.
- A 12-case deterministic Attack Lab corpus in
  `fixtures/attack_lab_cases.json`.
- New user-authorised evidence, charter, and execution operations are gated by
  Tripwire and then the host approval flow; there is no second approval engine.

Tripwire's scope is general-purpose: it evaluates tools used across research,
files, shell, APIs, messaging, databases, and development, not only coding
tools.

### Kairos

- Scoped environment fingerprints for the workspace, selected paths, system
  facts, tool presence, Git state when readable, and optional preconditions.
- Writes no file contents. Sensitive filenames and sensitive content are
  excluded, broad/remote/process state is not observed, and file walks are
  capped by configuration.
- Checkpoint-time snapshot and import-time diff. Levels are `GREEN` (no material
  change), `AMBER` (changed or unverified material state), and `RED` (material
  system or scope change).
- Reality diffs can stale Aletheia receipts that were recorded against the old
  environment.
- **It cannot guarantee TOCTOU safety.** A file can change after it is hashed
  and before it is used.

### Aletheia

- Evidence receipts for scoped observations: file hashes, positive test runs,
  command observations, and custom receipts.
- Receipt statuses include current, stale, superseded, and rejected. A receipt
  records what was checked and how; it does not prove factual correctness or
  future stability.
- Test receipts require a real positive test run; zero-test or failing runs are
  not treated as positive evidence.
- Protection is a challenge/approval layer, not immutability. A matching
  proposed mutation raises a host approval challenge, and a user can release
  protected work.
- Unverified accusations are stored as uncertain candidates and never erase
  evidence or protection.
- Environment changes and checkpoint imports can stale evidence and require
  memory re-verification.

### Telos

- Charters are created only from explicit `USER_AUTHORED` user text. External
  web, tool, or imported text cannot create or amend a charter.
- Versioned amendments record the user's explicit change, rationale, and audit
  trail.
- Stated constraints are checked against proposed actions; a conflict raises an
  approval hold rather than silently changing the plan.
- Drift advisories after a configurable number of actions without progress are
  advisory, not authorization.
- Completion scoring distinguishes verified completion from partial or
  unverified work and excludes prohibited constraints from success criteria.

### Moirai

- Deterministic, side-effect-free previews for supported file, shell, database,
  API, messaging, and development actions.
- Three explicit levels: `VERIFIED PREVIEW` for understood local operations,
  `PARTIAL PREVIEW` for requests whose remote or row-level effects cannot be
  established without executing, and `UNSUPPORTED PREVIEW` when effects cannot
  be safely predicted.
- Previews show plausible targets and consequences; they never execute the
  action, connect to an external service, or read file contents.
- Tripwire and the host approval flow remain the only authorization mechanisms.

### Metis

- Failure fingerprints keyed by tool, target, normalised arguments, and error
  shape.
- A temporary circuit opens after repeated identical failures without progress;
  changed strategy or arguments are not blocked.
- Preflight can stop a repeated unproductive operation before execution and
  offer alternatives.
- A user can close a circuit from the Console, CLI, or a confirmation-gated
  model tool. Circuits expire automatically and never become permanent denial.
- **It does not guarantee that every loop is caught.** Failures without a
  recognisable error shape or progress signal may not open a circuit.

### Hephaestus

- Distils a session's observed `tool_result_observed` trace into a playbook.
  Confidence is `successful_steps / steps_attempted`; retries with the same
  `(tool_name, sorted JSON params)` are deduplicated.
- Steps are split into a trusted verified procedure, failed anti-patterns, and
  source-labelled untrusted evidence. Untrusted evidence is quoted and
  explicitly excluded from the procedure; it never becomes an instruction.
- Forging writes a contained, checksummed `SKILL.md`, `blueprint.json`, and
  `manifest.json`, registers the skill and automation blueprint through the
  verified Hermes host surface, and issues a safety lease.
- A forge is preview-first and requires explicit confirmation. Refusal or
  quarantine is the default for untrusted-only traces, low confidence, path
  escapes, or already quarantined playbooks.
- Safety leases scope allowed tools, lexical path prefixes, domains, opaque
  tools, per-run tool/write/external-call budgets, expiry, Cron job binding,
  and a coarse platform/Python environment fingerprint.
- Unattended Cron enforcement is additive: a matching active lease can allow a
  scoped call, a violation blocks it, and no lease check ever grants host
  approval. A job with no matching forged playbook is unscoped; once a
  playbook matches, a missing, revoked, or expired lease blocks the bound job
  rather than silently unscoping it.
- Skill-write quarantine blocks generic writes to skill directories when the
  session's recorded source context includes untrusted external content.
- Quarantine blocks new leases and Cron checks. Already-loaded host registry
  entries may persist until the host reloads; immediate unregistration is not
  claimed.
- A separate 4-case Hephaestus Attack Lab covers poisoned source, path escape,
  lease budget, and environment drift. It is deterministic and synthetic, not a
  live security proof.

### Continuum Console

The plugin ships a real Hermes Desktop surface backed by its own HTTP API:

- **Overview** — live counts, recent events, security decisions, checkpoints,
  sources, and pending review.
- **Nine Systems** — pillar cards, latest reality state, evidence and
  protection counts, charter and drift state, previews, failures, circuits, and
  forged-artifact counts, plus a preview form.
- **Forge** — trace distillation form, preview/confirmation gate, forged
  playbooks, quarantine/release, lease issue/revoke, and the Hephaestus Attack
  Lab.
- **Timeline** — filterable Event Spine with event detail and module tabs for all
  nine systems.
- **Memory** — review queue, confirmed/rejected/history, confirm/reject/edit/
  forget actions, and dream runs.
- **Security & Checkpoints** — Tripwire decisions, the 12-case Attack Lab,
  retention, checkpoint export/inspect/import, and resume brief.
- Compact pane, status-bar counter, palette command, and keybind.
- Hidden dashboard tab plus API-only backend (`dashboard/plugin_api.py`) mounted
  at `/api/plugins/hermes-continuum/`.
- Uses Hermes Desktop theme variables, not a hardcoded palette.

## What is not claimed

The following are deliberately **not** claimed or not implemented:

- TOCTOU immunity. Kairos and Aletheia observe scoped state; they do not freeze
  the filesystem or guarantee that an artifact cannot change after observation.
- Rollback, undo, or reversal of external actions. Checkpoints restore
  plugin-owned records, not the outside world.
- Arbitrary shell simulation or universal impact prediction. Moirai labels
  unsupported or partial effects honestly and never executes a proposed action.
- Proof that a saved document is factually correct, that a command's exit code
  proves an outcome, or that a test receipt is a guarantee of quality.
- Immutability or deletion-proof protection. Aletheia protection is a
  challenge/approval layer that the user can release.
- Guaranteed detection or prevention of all retry loops. Metis circuits are
  temporary and heuristic.
- Perfect prompt-injection protection or generic proof of safety.
- Universal live acceptance of every system in this build. The verified subset
  is a host-mediated `continuum_status` turn, a live encrypted checkpoint export
  through the production Dashboard API, and the production Desktop Console
  rendering the live `continuum-live` profile. Live tool-scope blocking, lease
  revocation, quarantine consumption, fresh-process rehydration, checkpoint
  import, and a real Cron execution remain unverified.
- A normal one-click Desktop launch on the audit host. The host had an
  interrupted source update; the verified Desktop path used a manually started
  isolated backend and the production Electron app. The host update marker was
  not modified.

## Installation

### From a Hermes profile (recommended)

Hermes currently rejects a local directory with
`hermes plugins install <local-directory>` (`Invalid plugin identifier`). Use
the profile plugin directory instead:

```powershell
$plugin = (Resolve-Path .).Path   # run from the repository root
$profile = "your-profile"         # or omit -p for the default profile
$target = "$env:LOCALAPPDATA\hermes\profiles\$profile\plugins\hermes-continuum"

New-Item -ItemType Directory -Force -Path $target | Out-Null

# Runtime and supporting files. Do not copy evidence, tests, caches, or
# temporary profiles into a production profile.
$items = @(
    "plugin.yaml",
    "__init__.py",
    "continuum_core",
    "dashboard",
    "desktop",
    "fixtures",
    "README.md",
    "CHANGELOG.md",
    "docs"
)
foreach ($item in $items) {
    Copy-Item -Recurse -Force "$plugin\$item" $target
}

hermes -p $profile plugins enable hermes-continuum
```

The root `__init__.py`, `plugin.yaml`, `continuum_core/`, `dashboard/`, and
`desktop/` must stay together. Hermes copies the Desktop half to
`<HERMES_HOME>\desktop-plugins\hermes-continuum\` when the plugin is enabled.
`fixtures/` is needed for the Attack Lab.

### Dependencies

`plugin.yaml` declares a bounded dependency:

```yaml
python_dependencies:
  - "cryptography>=46,<51"
```

If safe encryption is unavailable, checkpoint actions fail closed with a clear
error; they do not fall back to plaintext.

### Live installation status

The isolated `continuum-live` profile on Hermes Agent `v0.22.2` loaded
`hermes-continuum` 0.3.0. `hermes -p continuum-live plugins doctor` reported 12
tools and 11 hooks. A fresh host-mediated tool turn produced
`continuum_status ok in 81 ms` in the Event Spine, and the production Desktop
Console rendered the live profile. A live checkpoint export through the
production Dashboard API produced an encrypted file that the Security &
Checkpoints view listed as `2 records · 1 file`.

Caveats are part of the evidence: the model was a local deterministic
OpenAI-compatible test fixture, not a production model; the host tool registry,
plugin, Event Spine, and Desktop were real. The normal one-click Desktop
launcher was blocked by the host's `.hermes-update-in-progress`; the audit used
a temporary local launcher that did not modify the host checkout or marker. A
real Hermes Cron job was not executed during verification; Cron lease
enforcement is covered by deterministic hook tests that inject the verified
`CronExecution` shape. See [VERIFICATION.md](VERIFICATION.md).

## Configuration

Settings are read through the host config getter and clamped to safe bounds.
These are the 32 keys exposed by the manifest:

| Key | Default | Meaning |
|---|---|---|
| `recall_limit` | `5` | Maximum confirmed/candidate facts returned by recall (1–10). |
| `episode_retention_days` | `30` | Retention for episodes and sources (1–3650). |
| `context_trust_window_minutes` | `30` | How long a source stays in the enforcement window (1–1440). |
| `tripwire_audit_allowed` | `true` | Record allowed sensitive decisions. |
| `enable_source_labels` | `true` | Append provenance labels to external tool results. |
| `enable_memory_capture` | `true` | Capture explicit user memory statements. |
| `dream_episode_limit` | `100` | Episodes per dream run (1–500). |
| `checkpoint_dir` | `""` | Optional checkpoint directory; defaults to plugin storage. |
| `enable_kairos` | `true` | Enable environment fingerprints and reality diffs. |
| `kairos_scope` | `""` | Optional workspace directory to fingerprint. |
| `kairos_max_files` | `200` | Files fingerprinted per snapshot (1–2000). |
| `kairos_max_file_bytes` | `2097152` | Largest file hashed (4 KiB–32 MiB). |
| `kairos_required_tools` | `""` | Comma-separated executables whose presence should be observed. |
| `enable_aletheia` | `true` | Enable evidence receipts, staling, and protected-work holds. |
| `enable_telos` | `true` | Enable charters, conflict checks, drift advisories, and completion scoring. |
| `telos_context_chars` | `900` | Maximum charter context injected before a model call (300–3000). |
| `telos_drift_after_actions` | `8` | Actions without progress before a drift advisory (3–100). |
| `enable_moirai` | `true` | Enable side-effect-free impact previews. |
| `moirai_max_items` | `50` | Maximum targets or effects listed in one preview (1–500). |
| `enable_metis` | `true` | Enable failure fingerprints and retry circuits. |
| `metis_failure_threshold` | `3` | Repeated identical failures before a circuit opens (2–20). |
| `metis_window_minutes` | `30` | Failure-counting window (1–1440). |
| `metis_circuit_minutes` | `30` | Circuit duration before automatic expiry (1–1440). |
| `enable_hephaestus` | `true` | Enable trace distillation, forging, leases, and Cron enforcement. |
| `hephaestus_artifact_dir` | `""` | Optional artifact root; defaults to plugin storage. Paths are contained to this root. |
| `hephaestus_min_confidence` | `0.5` | Minimum successful-step ratio before a trace may be forged without force (0.0-1.0). |
| `hephaestus_max_trace_events` | `5000` | Maximum session events considered per distillation (100-10000). |
| `hephaestus_max_steps` | `80` | Maximum verified steps retained in one forged skill (1-200). |
| `hephaestus_lease_minutes` | `1440` | Default safety-lease duration in minutes (5-43200). |
| `hephaestus_max_lease_days` | `30` | Maximum lease lifetime in days (1-365). |
| `hephaestus_cron_enforce` | `true` | Enforce matching safety leases in unattended Cron runs. |
| `hephaestus_quarantine_untrusted_skill_writes` | `true` | Block writes to skill directories when session context is untrusted. |

Three internal safety limits are read through the same config getter when
available but are not exposed in the manifest form: `max_recall_chars`
(1800; clamped 400–6000), `max_episode_excerpt_chars` (600; clamped 120–2000),
and `checkpoint_max_bytes` (32 MiB; clamped 1–128 MiB).

## Commands

### Model-facing tools

| Tool | Purpose |
|---|---|
| `continuum_status` | Read-only status and counts. |
| `continuum_recall` | Search confirmed/candidate memory with provenance labels. |
| `continuum_memory_review` | List, confirm, reject, edit, or forget memory. Mutations require host approval. |
| `continuum_dream` | Run deterministic consolidation over unprocessed episodes. |
| `continuum_checkpoint` | Export, inspect, or import an encrypted checkpoint. Export/import require host approval and an out-of-band passphrase. |
| `continuum_reality` | Snapshot or diff a scoped environment, optionally with preconditions. |
| `continuum_evidence` | Record, confirm, list, protect, or release evidence; inspect challenges. |
| `continuum_charter` | Create, amend, advance, or score a user-authored charter. |
| `continuum_preview` | Produce a non-executing impact preview for a proposed action. |
| `continuum_execution` | Inspect failure fingerprints/circuits or reset a circuit. |
| `continuum_forge` | Preview, confirm, inspect, or quarantine a trace-derived playbook and its forged artifacts. |
| `continuum_lease` | Issue, inspect, or revoke a bounded safety lease. A lease never grants host approval. |

All twelve handlers return JSON and never raise. User-authorised mutations
(evidence confirmation/protection/release, charter amendment/completion,
execution reset, forging, quarantine changes, and lease issue/revoke) require
explicit confirmation and are gated by Tripwire.

### CLI

```powershell
hermes continuum status
hermes continuum overview
hermes continuum config
hermes continuum timeline --limit 50
hermes continuum memory list --status candidate
hermes continuum memory confirm <fact-id>
hermes continuum memory reject <fact-id>
hermes continuum memory edit <fact-id> "new value"
hermes continuum memory forget <fact-id> --yes
hermes continuum dream
hermes continuum recall "deployment region"
hermes continuum attack-lab
hermes continuum retention --days 30 --yes
hermes continuum checkpoint list
hermes continuum checkpoint export --out .\checkpoints\handoff.hcc
hermes continuum checkpoint inspect .\checkpoints\handoff.hcc
hermes continuum checkpoint import .\checkpoints\handoff.hcc --yes
hermes continuum resume show
hermes continuum resume dismiss <brief-id>
hermes continuum reality list
hermes continuum reality snapshot --scope . --label before-change
hermes continuum reality diff
hermes continuum evidence list
hermes continuum evidence record-file .\report.md
hermes continuum evidence confirm <receipt-id> --yes
hermes continuum evidence protect .\report.md --yes
hermes continuum evidence release <protected-id> --reason "User requested" --yes
hermes continuum charter active
hermes continuum charter amend <charter-id> "New explicit scope" --yes
hermes continuum charter complete <charter-id> --evidence <receipt-id> --yes
hermes continuum preview run write_file --args-json "{\"path\":\"notes.md\"}"
hermes continuum execution list
hermes continuum execution reset <circuit-id> --yes
hermes continuum playbook list
hermes continuum playbook show <playbook-id>
hermes continuum playbook distill <session-id>
hermes continuum playbook quarantine <playbook-id> --yes
hermes continuum playbook unquarantine <playbook-id> --yes
hermes continuum forge <session-id>
hermes continuum forge <session-id> --allowed-tool read_file --allowed-path . --ttl-minutes 60 --yes
hermes continuum lease list
hermes continuum lease issue <playbook-id> --allowed-tool read_file --allowed-path . --ttl-minutes 60 --yes
hermes continuum lease revoke <lease-id> --reason "User requested" --yes
hermes continuum attack-lab --suite hephaestus
hermes continuum doctor
```

Checkpoint passphrases are read from `HERMES_CONTINUUM_PASSPHRASE`, an
interactive `getpass` prompt, or `--passphrase-stdin`; they are not accepted as
ordinary command-line arguments.

The 0.1.0 spellings `memory edit <fact-id> --value "new value"` and
`checkpoint import <path> --confirm` remain accepted as compatibility aliases.

### Slash command

```text
/continuum status
/continuum memory list --status candidate
/continuum checkpoint list
/continuum playbook list
/continuum lease
/forge list
/forge <session-id>
/forge <session-id> --yes
```

Slash commands intentionally expose only non-secret operations. `/forge`
previews unless `--yes` is present; use the CLI or Console for allowed tools,
paths, domains, budgets, expiry, or a Cron job id.

## Testing and verification

The formal suite is offline and uses temporary plugin databases and a recording
host context:

```powershell
python -m pytest tests -q
```

The submission-tree full offline run is **184 passed, 1 skipped, 1 third-party
Starlette/httpx deprecation warning, 163.00s** on Python 3.11.7. The skipped test
is the opt-in installed-host validator smoke; the earlier host-enabled run was
**185 passed, 1 warning, 506.25s**. The suite covers
manifest/loader contracts, migrations, idempotency, concurrency, redaction
canaries, policy cases, the 12-case Tripwire Attack Lab, the 4-case Hephaestus
Attack Lab, memory correction/dream/recall, checkpoint
encryption/tamper/import conflicts, runtime hook behaviour, tools/CLI, dashboard
endpoints, Console route parity, data isolation, installation loading, trace
distillation and forging, lease enforcement, quarantine, skill-write
protection, and Hephaestus service/dashboard integration.

The installed-host validator/doctor smoke test is opt-in: set `HERMES_LAUNCHER`
to a Windows Hermes launcher before running the suite. The validator and doctor
were also run separately against the pinned host; exact outputs are in
[VERIFICATION.md](VERIFICATION.md).

A passing offline suite is **not** live verification. It does not prove that
every system has received production-session acceptance or that the production
Desktop Console renders correctly on every host.

Also run from the repository root:

```powershell
python -m compileall -q continuum_core __init__.py tests dashboard
cmd /c "type desktop\plugin.js | node --input-type=module --check"
hermes plugins validate . --json
hermes plugins doctor . --ci
```

See [VERIFICATION.md](VERIFICATION.md) for exact recorded results and the live
evidence boundary.

## Security posture

- Fail closed on policy or storage errors for sensitive sinks.
- Block only high-confidence exfiltration; ask for ambiguous actions.
- Never let an LLM grant permission; approvals are host/user decisions.
- Never expose credentials or passphrases in logs, tool results, or the Console.
- Never silently promote uncertain information to confirmed memory.
- Keep Tripwire as the only policy engine. Aletheia, Telos, Metis, Moirai, and
  Hephaestus can raise holds, blocks, advisories, previews, quarantine, or
  lease violations, but they do not replace Tripwire or the host approval flow.
- Treat receipts, fingerprints, charters, previews, circuits, forged artifacts,
  and safety leases as scoped observations or constraints, not proof of safety.
- A safety lease is an additive unattended-execution constraint. Issuing or
  matching a lease never grants approval, never bypasses Tripwire, and never
  makes an otherwise-denied call allowed.
- Forged artifacts are untrusted until reviewed. The skill body excludes
  untrusted evidence, paths are contained to the artifact root, and writes
  require explicit confirmation, but a forged skill can still be wrong.
- Do not claim perfect prompt-injection protection. Source labels and
  enforcement are deterministic safeguards, not a proof.

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model, rules, and known
limitations.

## Known limitations

- The verification matrix in [VERIFICATION.md](VERIFICATION.md) distinguishes
  live-verified paths from test-covered-but-not-live-verified paths. Memory,
  evidence, charter, preview, execution reset, forge, lease, quarantine,
  checkpoint import, and Cron enforcement are not all live-verified in this
  build.
- No general plugin cron API for scheduling; dream consolidation is
  manual/CLI/Console-driven. Hephaestus reads the host's verified
  `current_cron_execution()` context when a Cron job runs.
- A real Hermes Cron job was not executed during verification. Cron lease
  enforcement is tested by injecting the verified `CronExecution` shape; live
  scheduler integration remains unverified.
- Forged skills and blueprints are registered through the verified host
  registrar, but a live reload/rehydration pass in a production profile was not
  performed. Quarantine cannot force immediate unregistration from an
  already-loaded host skill registry.
- Lease path checks are lexical normalization and prefix containment, not a
  kernel sandbox or symlink-resolution guarantee. Domain checks apply to
  URL-bearing external tools, and opaque tools must be explicitly allowed.
- Hephaestus is not a rollback system, an immutable artifact store, a TOCTOU
  guarantee, or a second approval engine.
- `hermes plugins install <local-directory>` is rejected; use the profile copy
  workflow above.
- A normal one-click Desktop launch on the audit host was blocked by an
  interrupted host source update. The verified Desktop path used a temporary
  launcher and a manually started isolated backend; the host update marker was
  not modified.
- Desktop source-update and initial-mount races were observed; the Console
  refreshes when the connection becomes ready.
- Kairos fingerprints are scoped and best-effort. They exclude sensitive
  filenames/content, skip broad/remote/process state, cap file walks, and cannot
  prevent TOCTOU changes.
- Aletheia receipts prove only what was observed in scope. They do not prove
  factual correctness, future stability, or that a command's exit code achieved
  the intended external outcome.
- Aletheia protection is not immutability. The user can release or change their
  own work, and destructive tools are handled by Tripwire/host approval, not by
  an undeletable lock.
- Telos drift is advisory and heuristic. Charters are created only from explicit
  user text; the system does not infer an unstated global goal.
- Moirai cannot simulate arbitrary shell commands or guarantee remote/row-level
  effects. Unsupported requests are labelled `UNSUPPORTED PREVIEW`.
- Metis circuits are temporary and fingerprint-based; they do not guarantee
  detection of every loop or failure mode.
- Terminal output from arbitrary commands is classified heuristically; only
  commands containing recognised network verbs are treated as external.
- Checkpoints move plugin-owned state only. They do not migrate live processes,
  GUI state, in-flight actions, or Hermes' private session database.
- `on_session_finalize` return-message behaviour is unverified and not used.
- The plugin is not published and is not in the Hermes catalog. The local commit
  and catalog PR preparation are complete; pushing, opening a PR, publishing,
  and posting remain explicit developer actions.

## Repository layout

```text
hermes-continuum/
├── .gitignore
├── LICENSE
├── README.md
├── CHANGELOG.md
├── VERIFICATION.md
├── DEMO_SCRIPT_90_SECONDS.md
├── SUBMISSION_CHECKLIST.md
├── plugin.yaml                 # manifest v2: 11 hooks, 12 tools, 32 config keys
├── __init__.py                 # loader entry: hooks/tools/CLI/slash
├── continuum_core/             # Event Spine, nine systems, checkpoints, adapters
├── dashboard/                  # hidden API backend + dist/index.js shim
├── desktop/plugin.js           # Continuum Console (SDK, no JSX)
├── fixtures/                   # 12-case Tripwire Attack Lab corpus
├── tests/                      # offline formal suite
└── docs/
    ├── ARCHITECTURE.md
    ├── SECURITY.md
    └── screenshots/            # live proof captured from the production Desktop
```

`dashboard/dist/index.js` is a required production asset, not a disposable
build artifact. Historical audit reports, raw evidence, local profiles, and
machine-specific runbooks are intentionally excluded from the public tree; the
originals remain in the developer workspace. See
[SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md) for the exclusion list.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — nine-system components, data
  flow, storage, hooks, checkpoint format, and compatibility boundaries.
- [docs/SECURITY.md](docs/SECURITY.md) — threat model, policy, approvals,
  evidence/protection boundaries, lease/quarantine boundaries, redaction,
  encryption, and limitations.
- [VERIFICATION.md](VERIFICATION.md) — exact live and offline verification
  results, commands, environment, and proof boundaries.
- [DEMO_SCRIPT_90_SECONDS.md](DEMO_SCRIPT_90_SECONDS.md) — sub-90-second
  hackathon demo using the live profile and production Desktop Console.
- [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md) — local Git state, catalog
  PR preparation, public file inventory, blockers, and developer-only actions.

## License and publication status

The plugin is licensed under the MIT License; see [LICENSE](LICENSE).
Copyright (c) 2026 Hermes Continuum contributors.

This repository is local submission preparation. A local Git commit is
prepared, but no remote, push, PR, catalog entry, release, or hackathon
submission has been created. Publication requires explicit developer action.
