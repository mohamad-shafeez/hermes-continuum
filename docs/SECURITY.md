# Hermes Continuum Security

**Revision:** 2026-11-10

**Plugin version:** `0.3.0`

**Schema version:** `3`

**Scope:** security model for the nine-system build

## 1. Security goals

Hermes Continuum is designed to improve five classes of behaviour without
pretending to solve prompt injection or prove safety:

1. **High-confidence credential exfiltration** is blocked deterministically.
2. **Sensitive, destructive, or ambiguous actions** require an explicit user
   decision; a model cannot grant itself permission.
3. **Provenance and history** are recorded so a user can inspect what happened,
   what was external or untrusted, and what was actually observed.
4. **Memory and evidence** remain reviewable: uncertainty is not silently
   promoted to fact, and evidence is scoped to what was checked.
5. **Repeated unproductive execution** can be paused temporarily without
   becoming permanent denial or a second policy engine.
6. **Reusable automation** is forged only from reviewed, source-labelled traces
   and is constrained by bounded leases that can add blocks but never grant
   approval.

Continuum is a safety layer, not a sandbox, antivirus, filesystem freeze, or
proof of safety.

## 2. Non-goals and unsupported claims

This release does **not** provide:

- TOCTOU immunity or a guarantee that a file cannot change after it is hashed.
- Rollback, undo, or reversal of external actions.
- Arbitrary shell simulation, universal impact prediction, or guaranteed
  prediction of remote/row-level effects.
- Proof that a saved document is factually correct, that a command's exit code
  achieved the intended external outcome, or that a test run guarantees quality.
- Immutability or deletion-proof protection. Aletheia protection is a
  challenge/approval layer and can be released by the user.
- Guaranteed detection or prevention of all retry loops.
- Perfect prompt-injection protection or a generic proof of safety.
- Live production acceptance of the new systems in this build.
- A kernel sandbox, rollback, or immutable artifact store for forged skills.
- A guarantee that a forged skill is correct or safe merely because it was
  distilled from a successful trace.
- Immediate unregistration of a quarantined skill from an already-loaded host
  registry.
- Live Cron execution or production skill/blueprint rehydration verification.

## 3. Trust model

- The **user** is the authority for approvals, memory confirmation, checkpoint
  passphrases, evidence confirmation/protection/release, charter amendments,
  completion, retention, circuit resets, forging, quarantine changes, and lease
  issue/revoke.
- The **host** enforces hook return values and displays the approval UI.
  Continuum never simulates an approval.
- **Tripwire** is the only deterministic policy engine. Aletheia, Telos, Moirai,
  Metis, and Hephaestus can add holds, conflicts, previews, preflight blocks,
  quarantine, or lease violations, but do not replace Tripwire or the host.
- **A safety lease** is a constraint on unattended execution. A matching lease
  never grants permission, never bypasses Tripwire, and never turns a denied
  action into an allowed one.
- **External content** (web pages, remote tool output, network terminal output)
  is untrusted regardless of how authoritative it appears.
- **Local tool output** is local provenance, not truth.
- **Models** may propose actions and candidate facts; they cannot confirm memory,
  approve their own action, amend a charter, or reset a circuit without the
  user-confirmed host path.

### Trust labels

The store distinguishes:

- `USER_AUTHORED`
- `UNTRUSTED_EXTERNAL`
- `LOCAL_TOOL_OUTPUT`
- `PLUGIN_GENERATED`
- `DERIVED_FROM_SOURCE`
- `UNKNOWN`

A provenance label describes where content came from. It does not establish that
the content is correct.

## 4. Enforcement path

`pre_tool_call` is the enforcement hook:

1. Resolve the session's source context within the configured trust window. An
   earlier untrusted external source remains visible even if a newer local read
   occurs.
2. Evaluate Tripwire.
3. Audit non-allow decisions and configured allowed sensitive decisions.
4. Run Metis preflight; it can block only when Tripwire has not already blocked.
5. Return a Tripwire block, if any.
6. Add Aletheia protected-work challenges.
7. Add Telos explicit-constraint conflicts.
8. Attach a Moirai preview for approvals or sensitive actions.
9. When `current_cron_execution()` identifies a Cron run, evaluate active
   Hephaestus lease bindings. A violation adds a block; a matching allow does not
   remove the Tripwire decision or grant approval.
10. Block generic skill-directory writes when the session source context is
    untrusted and the skill-write quarantine is enabled.
11. Return one combined approval request when holds exist, or the Tripwire
    decision otherwise.
12. Fail closed if policy or storage cannot be trusted for sensitive actions.

Aletheia and Telos holds are approval triggers, not a second approval engine.
Hephaestus lease checks are additive blocks, not an approval source. The host
still decides. There is no code path where a model confirms its own permission.

### Failure behaviour

- Tripwire evaluation failure: **block**.
- Audit store unavailable, sensitive sink: **approve** with a warning, not silent
  allow.
- Audit store unavailable, ordinary action: static Tripwire decision applies.
- Metis/Aletheia/Telos/Moirai observer failure: log and continue without
  changing Tripwire's decision.
- Hephaestus lease lookup or usage-store failure during a Cron run: fail closed
  for that call; do not treat a failed lookup as permission. A job with no
  matching forged playbook remains unscoped; a job that matches a playbook but
  has no usable active lease blocks.
- Checkpoint crypto unavailable: fail closed; no plaintext fallback.

## 5. Tripwire policy and provenance

Tripwire is deterministic and local. It does not ask an LLM whether an action is
safe.

### Block

High-confidence credential-to-network exfiltration is blocked. This includes
recognised secret material paired with a network sink in the same action.

### Approve

Approval is required for classes including:

- destructive broad operations;
- remote script execution;
- persistence changes;
- credential-file reads;
- protected-path writes;
- external side effects;
- sensitive actions in an untrusted context;
- model-facing Continuum state changes;
- evidence confirmation/protection/release, charter amendment/completion, and
  execution reset exposed through model tools.

### Allow

Ordinary reads and non-sensitive local actions proceed.

### Provenance labels

External tool results receive an additive provenance banner where supported.
`write_file`, `patch`, and `skill_manage` are never transformed by Continuum;
`security-guidance` remains authoritative for those results. Continuum tools are
also excluded to avoid recursive annotation.

Terminal output from arbitrary commands is classified heuristically. A command
must contain a recognised network verb to be treated as an external source.
This is a heuristic, not a guarantee that all remote content is recognised.

## 6. Aletheia evidence and protected work

### What a receipt proves

A receipt records a scoped observation:

- a file was hashed at a point in time;
- a positive test command produced a recognised passing result;
- a command or custom observation was recorded;
- the environment hash/snapshot associated with the observation, when available.

It does **not** prove factual correctness, future stability, that a test suite is
meaningful, or that a command achieved its intended external effect. Zero-test
runs and failing runs are not accepted as positive evidence.

### Protection boundary

Aletheia protection is a **challenge/approval layer**:

- a matching proposed mutation raises a host approval challenge;
- the challenge is resolved after the tool result;
- the user can release protection;
- destructive actions still depend on Tripwire and host approval.

It is not immutability, a filesystem lock, or a guarantee that protected work
cannot be changed. No claim of deletion-proof protection is made.

### Staling and accusations

- Environment changes can stale receipts recorded against the old hash.
- Staling marks linked memory for re-verification; it does not rewrite the
  user's confirmed value.
- Unverified accusations are stored as low-confidence candidates and never erase
  evidence or protection.

## 7. Telos goal integrity

- Charters can be created or amended only from explicit `USER_AUTHORED` input.
  External web/tool/imported text cannot create or amend a charter.
- Amendments are versioned with rationale and audit events.
- A proposed action that conflicts with an explicit user constraint raises an
  approval hold; the system does not silently reinterpret the goal.
- Drift detection is advisory and heuristic. It does not authorize actions and
  does not prove that the model has gone off-task.
- Completion scoring distinguishes verified, partial, and unverified work.
  Prohibited constraints are excluded from success criteria.

## 8. Kairos reality and TOCTOU

Kairos fingerprints a scoped environment:

- selected workspace paths or explicit paths;
- system facts and optional required tools;
- readable Git state;
- optional preconditions.

It does not store file contents. Sensitive filenames/content are excluded, broad
and remote state is not observed, and file walks/hashes are capped.

A reality diff reports `GREEN`, `AMBER`, or `RED` and lists changed/unverified
material state. A non-GREEN diff can stale evidence.

**Kairos cannot prevent a time-of-check/time-of-use race.** A file can change
between the hash and the later use. It also cannot observe remote services,
process memory, or state outside its configured scope.

## 9. Moirai impact previews

Moirai never executes the proposed action, connects to a remote service, or
reads file contents. Its preview is a deterministic description of plausible
targets and consequences.

- `VERIFIED PREVIEW` means a local operation is understood.
- `PARTIAL PREVIEW` means the request shape is known but remote or row-level
  effects cannot be verified without executing.
- `UNSUPPORTED PREVIEW` means effects cannot be safely predicted.

A preview is advisory. It is not approval, proof of safety, or a complete
enumeration of side effects.

## 10. Metis execution resilience

Metis fingerprints repeated failed executions by tool, target, normalised
arguments, and error shape.

- A circuit opens after repeated identical failures without progress.
- A changed strategy/arguments is not blocked by the same circuit.
- Preflight can block before execution only when Tripwire has not already
  blocked.
- A user can reset a circuit after confirmation; circuits also expire.
- Circuits are temporary and heuristic. They do not guarantee detection of every
  loop and never become permanent denial.

## 11. Hephaestus forging, leases, and quarantine

### Trace trust boundary

- Hephaestus distils only recorded `tool_result_observed` steps, bounded by
  configuration. Confidence is `successful_steps / steps_attempted`; a high
  ratio is not proof that the procedure is correct or safe.
- Steps are split into verified successes, failed anti-patterns, and
  source-labelled untrusted evidence. Untrusted evidence is quoted and excluded
  from the generated procedure; it is never interpolated as an instruction.
- Retries are deduplicated by `(tool_name, json.dumps(params, sort_keys=True))`
  so repetition cannot inflate confidence.
- Forging refines an untrusted-only trace as `forge_refused`, and a path escape
  is rejected rather than written.

### Forging boundary

- A preview is side-effect free. `forge` requires explicit user confirmation
  (`--yes` / `confirm=true`) and always re-checks confidence, trust, and path
  containment at write time.
- Artifacts (`SKILL.md`, `blueprint.json`, `manifest.json`) are written
  atomically under the plugin artifact root, with checksums recorded.
- Forged skills and blueprints are registered through `PluginHostRegistrar`,
  which wraps the verified host `register_skill` and
  `register_automation_blueprint` contracts.
- Rehydration is lazy and re-checks containment, checksums, and database
  quarantine status. It is not a proof that the artifact content is benign.
- A forged skill can still be wrong. Review before reuse is required.

### Safety-lease boundary

A lease scopes:

- allowed tool names;
- lexically normalized path prefixes;
- allowed domains for URL-bearing external tools;
- whether opaque tools are permitted (default: denied);
- per-run tool-call, file-write, and external-call budgets;
- expiry and an optional Cron job binding;
- a coarse platform/Python environment fingerprint.

The boundary is intentionally conservative, but it is not a kernel sandbox.
Path checks are lexical containment, not OS-level isolation. `web_search` may run
without a domain match; URL-bearing external tools require an allowed domain.
Opaque tools must be explicitly allowed. An environment fingerprint mismatch
blocks the lease.

Budgets are per Cron `execution_id`/run, not global. Blocked calls do not consume
budget. A revoked or expired lease still identifies its bound `cron_job_id` and
blocks that job rather than silently unscoping it. An active lease whose playbook
is quarantined also blocks.

### Cron enforcement boundary

- Enforcement uses the verified `CronExecution` fields: `job_id`, `job_name`,
  `execution_id`, `source`, `scheduled_instant`, `started_at`, and `profile`.
  The job prompt is not exposed, and `current_cron_execution()` returns `None`
  in delegated child contexts.
- A matching lease can allow a scoped call. It never grants host approval and
  never overrides a Tripwire block or approval.
- A real Hermes Cron job was not executed during verification. The enforcement
  path is tested by injecting the verified `CronExecution` shape.

### Quarantine boundary

- Quarantine blocks new leases and Cron checks, updates the artifact manifest,
  and prevents rehydration.
- It does not force immediate unregistration from an already-loaded host skill
  registry. A live reload is required for that guarantee, and it is not claimed.
- Generic writes to skill directories are blocked when session source context is
  untrusted and the skill-write quarantine is enabled.

### Attack Lab

The Hephaestus Attack Lab is a separate deterministic 4-case suite: poisoned
source, path escape, lease budget, and environment drift. The original Tripwire
suite remains exactly 12 cases. Synthetic cases are regression checks, not a
proof of live safety.

## 12. Oneiros memory security

- Candidate facts are proposals, not established truth.
- Only explicit review promotes a candidate to confirmed.
- Edits create new versions; corrections supersede instead of deleting history.
- Confirmed values are preserved during checkpoint conflict handling; an
  imported conflicting value is proposed as a candidate.
- Recall labels candidates as unverified and excludes superseded versions.
- Evidence-aware re-verification adds uncertainty; it does not silently rewrite
  the user's memory.

## 13. Checkpoint security

### Encryption and authentication

- AES-256-GCM with scrypt key derivation (`n=2**14, r=8, p=1`).
- The manifest is authenticated as additional data; a checkpoint cannot be
  silently re-labelled or have its counts changed.
- The encrypted file envelope remains format `1`.
- The format-2 manifest and additive payload schema `1` carry the new tables and
  environment data. Old bundles without Hephaestus tables remain importable.
- Wrong passphrase, tampered ciphertext/manifest, checksum mismatch, unsupported
  future payload schema, oversized files, and identity disagreement are
  rejected.
- Writes are atomic and use restrictive permissions where the platform permits.

### Passphrases

Checkpoint passphrases come from:

- `HERMES_CONTINUUM_PASSPHRASE`;
- interactive CLI `getpass`;
- CLI `--passphrase-stdin`;
- the Console HTTP body, handled by the local backend.

Passphrases are never accepted as model-visible tool arguments, persisted, or
logged.

### Data included and excluded

Included: all plugin-owned tables, including the additive systems' records and
Hephaestus playbooks, leases, usage counters, and artifact metadata. Artifact
file bytes remain in the plugin artifact directory; checkpoints move metadata,
not live registrations.

Excluded: credentials, raw tool results, transcripts, Hermes private session
data, in-flight approvals/runtime state, and external side effects.

Import does not replay historical tool calls. It restores plugin records only.
Import into a different installation is reported AMBER because the installation
identity differs; this is expected.

## 14. Console and API security

- The backend is local to the Hermes Desktop plugin host and mounted at
  `/api/plugins/hermes-continuum/`.
- The router does not add its own network authentication layer; it assumes the
  host's local API boundary. Do not expose the plugin API as a public service.
- Dashboard checkpoint export is restricted to the plugin checkpoint directory;
  arbitrary destination paths are rejected.
- Destructive Console actions are explicit user actions, not model tool calls.
- Passphrases are not included in tool schemas or logs.
- Memory, evidence, charter, preview, circuit, playbook, lease, and artifact
  views expose only plugin-owned, redacted records.
- Forge and lease mutations require confirmation in model tools and explicit
  user actions in the Console/CLI.

## 15. Data isolation and redaction

- The plugin opens only its own profile database.
- Hermes' private session database is never opened or modified.
- Event details, memory excerpts, source references, previews, evidence
  metadata, and failure fingerprints pass through deterministic redaction and
  length bounds.
- Secret canaries are checked by tests to ensure exports and audit records do
  not contain known secret material.
- Raw external results are not stored wholesale.
- The isolation test suite verifies that the plugin does not reach outside its
  data boundary.

Redaction is best-effort. It cannot identify every possible secret format.

## 16. Residual risks

1. **Prompt injection remains possible.** Source labels and approvals reduce
   risk; they do not eliminate it.
2. **TOCTOU remains possible.** A hash is a point-in-time observation.
3. **Evidence can be misleading.** A passing test can be incomplete or unrelated
   to the user's actual goal.
4. **Protection is not a lock.** A user can release it, and destructive actions
   still depend on policy and approval.
5. **Goal drift detection is heuristic.** It can miss drift or flag legitimate
   work.
6. **Impact previews are incomplete.** Remote, row-level, and complex shell
   effects may be partial or unsupported.
7. **Retry circuits are heuristic.** A loop without a recognisable failure shape
   may not be caught.
8. **Terminal provenance is heuristic.** Only recognised network verbs mark
   output as external.
9. **Checkpoint restoration is not rollback.** External actions and live state
   are not reversed.
10. **Forged artifacts can be wrong.** Distillation excludes untrusted evidence
    from the procedure, but a successful trace is not proof of correctness.
11. **Leases are lexical constraints, not a sandbox.** Path normalization and
    prefix containment, domains, opaque-tool denial, and coarse environment
    fingerprints do not stop every escape or TOCTOU change.
12. **Quarantine is not immediate unregistration.** An already-loaded host
    registry may retain a skill until reload.
13. **Cron enforcement is not live verified.** No real Hermes Cron job was run;
    tests inject the verified execution shape.
14. **Live production acceptance is absent for the new systems.** Offline tests
    and static registration are not a live-host proof.

## 17. Verification and incident expectations

The offline suite includes policy cases, both Attack Lab suites, redaction
canaries, migration tests, checkpoint tamper/wrong-passphrase tests, isolation
tests, runtime ordering, Hephaestus forging/lease/quarantine tests, and
nine-system integration. Static validation and doctor registration pass. These
checks do not replace a live security review in the deployment environment.

If a security issue is suspected:

1. Stop the affected action and do not rely on the audit history alone.
2. Inspect the Event Spine, security decisions, and any evidence receipts.
3. Release or reset the relevant protection/circuit only as an explicit user
   decision.
4. Preserve checkpoint files and logs without sharing passphrases.
5. Re-run the offline suite and a live host smoke test after remediation.

No security bounty, external audit, or production certification is claimed.
