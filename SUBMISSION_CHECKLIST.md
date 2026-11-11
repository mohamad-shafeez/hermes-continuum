# Submission Checklist - Hermes Continuum 0.3.0

**Prepared:** 2026-11-11

**Status:** local submission preparation complete; publication is a developer
action.

**Plugin:** `hermes-continuum` `0.3.0`

**Pinned host used for live proof:** Hermes Agent `v0.22.2`, commit
`d923a5eb487a17c0a68801bba9ef0f56c81040a8`

**Profile:** isolated `continuum-live`

This file records the exact local state, the public-file boundary, the catalog
PR preparation, and the remaining blockers. It does **not** claim that the
plugin is published, pushed, in the catalog, released, or submitted to the
hackathon.

## 1. What is complete

- Local Git repository initialized with a single submission commit prepared.
- Public tree staged from the repository root; local-only audit material excluded
  through `.git/info/exclude` and retained on disk.
- Current-facing README, CHANGELOG, MIT `LICENSE`, `VERIFICATION.md`, this
  checklist, and a sub-90-second demo script.
- Three live Desktop screenshots selected under `docs/screenshots/`.
- Clean-tree plugin validator: **15/15 checks, `warnings: []`, exit 0**.
- Plugin doctor: **12 tools, 11 hooks**, exit 0.
- Submission-tree full offline suite: **184 passed, 1 skipped, 1 warning,
  163.00s**; the skip is the opt-in installed-host validator test.
- Catalog entry template prepared below with the required fields and full-SHA
  pin rule.

## 2. Frozen implementation

The plugin implementation was not expanded or redesigned for submission. The
only tracked code-adjacent edit after the live audit was removing a hardcoded
local Hermes launcher path from `tests/test_installation.py`; the installed-host
smoke test is now opt-in through `HERMES_LAUNCHER`. No core service, tool, hook,
schema, Dashboard route, Desktop bundle, or fixture behavior was changed.

## 3. Git state and exact commands

Repository branch: `master`
Remote: **none configured**
Commit: local only; run `git rev-parse HEAD` for the full 40-character SHA
Working tree after the final commit: **clean** (`git status --short` prints
nothing)

Commands used to prepare the commit:

```powershell
git add -A
git diff --cached --name-only
git commit -m "Prepare Hermes Continuum 0.3.0 submission"
git status --short
git rev-parse HEAD
git remote -v
```

Expected final state:

```text
$ git status --short
# no output

$ git remote -v
# no output (no remote)
```

Do not push this commit until the developer has created or chosen the public
repository. The commit SHA is deliberately not embedded in this file: a file
cannot contain the SHA of the commit that adds it without creating a different
commit. Record the SHA returned by `git rev-parse HEAD` in the local handoff and
use that exact value in the catalog entry.

## 4. Public-file boundary

The public commit contains the plugin, its production assets, tests, current
documentation, and selected live screenshots. It excludes local audit reports,
raw API payloads, historical blueprints, machine profiles, databases, and
checkpoint files.

### Complete tracked inventory (81 files)

```text
.gitignore
__init__.py
CHANGELOG.md
continuum_core/__init__.py
continuum_core/adapters/__init__.py
continuum_core/adapters/cli.py
continuum_core/adapters/tools.py
continuum_core/aletheia/__init__.py
continuum_core/aletheia/service.py
continuum_core/checkpoint/__init__.py
continuum_core/checkpoint/bundle.py
continuum_core/checkpoint/crypto.py
continuum_core/checkpoint/resume.py
continuum_core/common/__init__.py
continuum_core/common/config.py
continuum_core/common/errors.py
continuum_core/common/ids.py
continuum_core/common/redaction.py
continuum_core/common/time.py
continuum_core/constants.py
continuum_core/hephaestus/__init__.py
continuum_core/hephaestus/artifacts.py
continuum_core/hephaestus/attack_lab.py
continuum_core/hephaestus/service.py
continuum_core/kairos/__init__.py
continuum_core/kairos/service.py
continuum_core/metis/__init__.py
continuum_core/metis/service.py
continuum_core/moirai/__init__.py
continuum_core/moirai/service.py
continuum_core/oneiros/__init__.py
continuum_core/oneiros/dream.py
continuum_core/oneiros/memory.py
continuum_core/oneiros/recall.py
continuum_core/runtime.py
continuum_core/service.py
continuum_core/spine/__init__.py
continuum_core/spine/schema.py
continuum_core/spine/store.py
continuum_core/telos/__init__.py
continuum_core/telos/service.py
continuum_core/tripwire/__init__.py
continuum_core/tripwire/attack_lab.py
continuum_core/tripwire/policy.py
continuum_core/tripwire/sources.py
dashboard/dist/index.js
dashboard/manifest.json
dashboard/plugin_api.py
DEMO_SCRIPT_90_SECONDS.md
desktop/plugin.js
docs/ARCHITECTURE.md
docs/SECURITY.md
docs/screenshots/continuum-security-checkpoints-fresh.png
docs/screenshots/continuum-security-fresh.png
docs/screenshots/continuum-timeline-fresh.png
fixtures/attack_lab_cases.json
LICENSE
plugin.yaml
README.md
SUBMISSION_CHECKLIST.md
tests/conftest.py
tests/pytest.ini
tests/test_aletheia.py
tests/test_checkpoint.py
tests/test_dashboard.py
tests/test_eight_system_integration.py
tests/test_hephaestus.py
tests/test_installation.py
tests/test_isolation.py
tests/test_kairos.py
tests/test_manifest.py
tests/test_memory.py
tests/test_metis.py
tests/test_migrations.py
tests/test_moirai.py
tests/test_policy.py
tests/test_runtime.py
tests/test_store.py
tests/test_telos.py
tests/test_tools_cli.py
VERIFICATION.md
```

`dashboard/dist/index.js` is a required production asset. `docs/screenshots/`
contains only the three selected live captures. `tests/pytest.ini` is included
for reproducibility.

### Excluded from the public commit but retained on disk

`.git/info/exclude` (local Git metadata, not committed) excludes:

```text
API_SURFACE_REPORT.md
AUDIT_HANDOVER_2026-11-11.md
CLEANUP_MANIFEST.md
CLEANUP_PROPOSAL.md
FINAL_EIGHT_SYSTEM_IMPLEMENTATION_REPORT.md
FINAL_NINE_SYSTEM_IMPLEMENTATION_REPORT.md
FINAL_REPORT.md
IMPLEMENTATION_STATUS.md
REPOSITORY_AUDIT_REPORT.md
TECHNICAL_VERIFICATION_REPORT.md
Hermes_Continuum_Expansion_Blueprint_8_Systems.md
Hermes_Continuum_Master_Blueprint.pdf
evidence/
docs/history/
```

These files contain historical claims, raw live payloads, host-specific paths,
or superseded reports. They are **not deleted**; they remain in the developer
workspace. Do not add them to the public repository without a separate privacy
and accuracy review.

## 5. Sanitization checks

- `git grep --cached` found no Windows user-profile paths, absolute repository
  paths, host user names, or live session-token values in the staged tree.
- Deliberate fake provider strings remain only inside the test code as
  redaction canaries. They are not live credentials and are confined to tests.
- No `.env`, profile database, checkpoint `.hcc`, log, `node_modules`, or cache
  directory is tracked.
- `README.md` uses `$env:LOCALAPPDATA` and a `(Resolve-Path .).Path` variable, not
  a machine-specific install path.
- `tests/test_installation.py` no longer hardcodes a local launcher path.
- The three screenshots were visually inspected: they show the local
  `127.0.0.1:52750` gateway, `continuum-live` profile, Event Spine rows, and the
  checkpoint file. They contain no passphrase, token, personal name, or local
  filesystem path.
- `LICENSE` uses "Hermes Continuum contributors" to avoid publishing a personal
  name. The developer can replace it before release if desired.

## 6. Verification commands and exact results

### Plugin validator on the clean public tree

```powershell
# Export the index to a clean directory, then validate that directory.
git checkout-index -a --prefix="<clean-dir>/"
hermes plugins validate <clean-dir> --json
```

Recorded result:

```text
"ok": true
15 checks, all true
"warnings": []
"isolation": { "verdict": "host", "host_ready": true, "reasons": [] }
exit 0
```

The checks are manifest, manifest fields, `requires_hermes`, config schema,
`requires_env`, loadable entry, Python dependencies, capability probe, declared
tools, declared hooks, declared middleware, built-in tool collisions, security
scan, no core override, and Desktop surface.

### Plugin doctor

```powershell
hermes plugins doctor <repository> --ci
```

Recorded result:

```text
Plugin Doctor: <repository>
  manifest: hermes-continuum 0.3.0 (standalone)
  OK: runtime discovery, manifest parsing, import, and registration passed
  registrations: 12 tool(s), 11 hook(s)
```

Exit code: `0`.

### Offline suite

```powershell
python -m pytest tests -q
```

Recorded on the submission tree:

```text
184 passed, 1 skipped, 1 warning in 163.00s (0:02:42)
```

The skip is the opt-in installed-host validator/doctor smoke test. The earlier
host-enabled run was `185 passed, 1 warning in 506.25s`. The warning is a
third-party Starlette/httpx deprecation warning.

### Catalog CI dependency install

```powershell
hermes plugins validate <repository> --json --install-deps
```

Attempted on the audit host. It reached:

```text
→ Resolving Python dependencies…
✓ Resolving Python dependencies
→ Installing Python dependencies…
```

and did not finish within 600 seconds. It was stopped by the command timeout.
**The dependency-install pass is not verified.** Re-run it on a clean,
network-enabled host or in the catalog CI environment before opening the PR.

## 7. Catalog PR preparation

Official requirements, from the pinned host's
`plugin-catalog/README.md` and `scripts/validate_plugin_catalog.py`:

- Entry file: `plugin-catalog/<name>.yaml` in the `hermes-agent` repository.
- One entry per plugin; additions land through a reviewed PR, not self-service.
- Required keys: `name`, `repo`, `sha`, `description`, `maintainer`.
- `repo` must be an HTTPS URL.
- `sha` must be exactly 40 lowercase hexadecimal characters. No branch, tag, or
  short SHA.
- `name` must match `[a-z0-9_-]{1,64}`. Use `hermes-continuum`.
- `tier` is `official` or `community`; use `community` unless the vendor says
  otherwise.
- `category` is one of `desktop`, `memory`, `platform`, `web`, `tools`, `voice`,
  `automation`, `models`, `general`; `desktop` is appropriate for this plugin.
- Optional fields must be truthful: `version`, `requires_hermes`, `subdir`,
  `capabilities`, `platforms`, `docs_url`, `image`, `screenshots`, `readme`.
- The plugin must not self-update. It must not ship binaries, bytecode, or
  unscannable payloads. Credentials must come through Hermes.
- Catalog CI runs `hermes plugins validate <path> --install-deps`.

### Entry template

Replace `<OWNER>` and `<40-HEX-COMMIT-SHA>` before committing the entry. Use the
SHA of the pushed public commit, not a local working-tree state.

```yaml
name: hermes-continuum
repo: https://github.com/<OWNER>/hermes-continuum
sha: <40-HEX-COMMIT-SHA>
description: "Nine-system Hermes plugin for portable work state, reviewed memory, evidence, previews, security, leases, and verified trace distillation, with a Desktop Console."
maintainer: <GITHUB-HANDLE>
tier: community
category: desktop
requires_hermes: ">=0.22.2"
version: "0.3.0"
platforms: [windows, macos, linux]
```

Do **not** add `capabilities:` unless it is generated from the pinned manifest and
matches the actual registrations. The validator checks declared capabilities
against reality; an incomplete optional block is worse than omitting it.

### Catalog validation

Standalone schema check (no Hermes install needed):

```powershell
python scripts/validate_plugin_catalog.py plugin-catalog/hermes-continuum.yaml --json
```

Expected:

```json
{ "ok": true, "files": [ { "ok": true, "errors": [], "warnings": [] } ] }
```

Full admission check at the pinned public commit:

```powershell
git clone https://github.com/<OWNER>/hermes-continuum.git
cd hermes-continuum
git checkout <40-HEX-COMMIT-SHA>
hermes plugins validate . --json --install-deps
```

The second command must be completed on a clean host or in CI. It is the only
remaining catalog-admission command that did not finish here.

### PR steps (developer action)

```text
1. Create the public repository and push the local master branch.
2. Confirm the pushed commit SHA with `git rev-parse HEAD`.
3. Add `plugin-catalog/hermes-continuum.yaml` to a clone of hermes-agent.
4. Run the standalone catalog validator and the --install-deps admission check.
5. Open a PR with the entry, a summary, and the live/offline proof boundary.
6. Wait for a maintainer review; do not self-merge.
```

Do not push, open the PR, or post the submission until the developer explicitly
authorizes it.

## 8. Blockers and unverified boundaries

| Blocker or gap | Status | Impact |
|---|---|---|
| No public Git remote or owner identity configured | **Blocked** | Catalog repo URL, push, and PR cannot be finalized. |
| `--install-deps` timed out after 600s | **Blocked** | The catalog CI dependency-install gate is not verified. |
| Host `.hermes-update-in-progress` blocks the normal launcher | **Workaround used** | Verified Desktop path used a temporary local launcher; the host marker was not modified. |
| Backend on `127.0.0.1:52750` is currently down | **Expected** | The recorded screenshots remain valid; restart the backend before recapturing. |
| Only checkpoint export is a live-verified mutation | **Partial** | The other 26 Dashboard mutation routes are test-covered only. |
| Real Cron, lease revocation, tool-scope block, quarantine consumption, checkpoint import, fresh-process rehydration | **Not live-verified** | Do not claim them in the demo or submission copy. |
| Local deterministic model fixture | **Disclosed test fixture** | The host tool call and Event Spine are real; the model is not a production model. |

See [VERIFICATION.md](VERIFICATION.md) for the full matrix and exact evidence.

## 9. Proof boundaries for the submission copy

Safe to say:

- The plugin loads on Hermes Agent `v0.22.2` in an isolated profile.
- The host registered 12 tools and 11 hooks.
- A host-mediated `continuum_status` call produced an Event Spine row
  `continuum_status ok in 81 ms`.
- The production Desktop Console rendered the live profile, Timeline, and
  encrypted checkpoint list.
- 15 Dashboard GET routes returned HTTP `200`; checkpoint export was exercised
  live.
- The clean public tree passes the plugin validator with no warnings.
- The offline suite passes on the submission tree.

Do not say:

- "All nine systems are live-verified."
- "This was a production model run."
- "The normal one-click Desktop launch works on this host."
- "Checkpoint import was verified live."
- "Every Dashboard mutation route was exercised."
- "The plugin is in the Hermes catalog."
- "The plugin is published, released, or submitted."

## 10. Developer-only actions remaining

1. Choose the public repository URL and push the local commit.
2. Record the exact pushed SHA in the catalog YAML and the handoff.
3. Run `hermes plugins validate . --json --install-deps` on a clean host or in
   CI and record the result.
4. Confirm whether the copyright holder should remain "Hermes Continuum
   contributors" or be changed before release.
5. Confirm the catalog maintainer handle and category.
6. Open the catalog PR and respond to review.
7. Publish the repository, demo, and hackathon submission only after explicit
   authorization.

No push, PR, release, catalog entry, or social post has been created by this
preparation.
