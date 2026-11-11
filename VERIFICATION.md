# Verification Record

**Build:** Hermes Continuum `0.3.0`

**Date:** 2026-11-11

**Pinned host:** Hermes Agent `v0.22.2`, commit
`d923a5eb487a17c0a68801bba9ef0f56c81040a8`

**Isolated profile:** `continuum-live`

This document separates what was observed on the real pinned host from what is
only covered by the offline suite. A test pass is not a live verification, and a
live read-only check is not proof that every mutation path works.

## Status vocabulary

| Status | Meaning |
|---|---|
| **VERIFIED** | Observed on the pinned host with the production plugin, or reproduced by an exact command whose output is recorded here. |
| **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Code and offline tests exist, but the path was not exercised on the pinned host. |
| **PARTIALLY IMPLEMENTED** | Some sub-paths work; the scope is explicitly limited. |
| **UNSUPPORTED BY PINNED HERMES VERSION** | The pinned host does not expose a surface needed for the claim. |
| **NOT IMPLEMENTED** | Deliberately out of scope. |
| **UNKNOWN** | Not enough evidence either way. |

## Environment

| Item | Value |
|---|---|
| Host runtime | Hermes Agent `v0.22.2` |
| Host commit | `d923a5eb487a17c0a68801bba9ef0f56c81040a8` |
| Plugin | `hermes-continuum` `0.3.0`, schema `3` |
| Profile | `continuum-live` |
| Host Python (runtime) | 3.14.7 |
| Test Python | 3.11.7 |
| Desktop | Production Electron app from the pinned host checkout |
| Model used for the recorded tool turn | Local deterministic OpenAI-compatible fixture, **not a production model** |

The host tool registry, plugin loader, Event Spine, Dashboard API, and Desktop
were real. The fixture only supplied model output that requested the real
`continuum_status` tool. It did not mock the tool, inject a result, or
pre-populate the Timeline.

## Live verification

### 1. Plugin load and doctor

The repository was checked with the pinned plugin doctor:

```text
Plugin Doctor: <repository>
  manifest: hermes-continuum 0.3.0 (standalone)
  OK: runtime discovery, manifest parsing, import, and registration passed
  registrations: 12 tool(s), 11 hook(s)
```

Exit code: `0`.

The isolated profile reported `hermes-continuum` `0.3.0` enabled and loaded the
same production plugin. The installed copy matched the repository for the
manifest, loader, core service/runtime, CLI/tools, Dashboard API/dist, Desktop
bundle, and Attack Lab fixtures.

**Status: VERIFIED.**

### 2. Catalog-admission validator

Command run against the repository:

```powershell
hermes plugins validate <repository> --json
```

Result: `"ok": true`; all 15 checks passed; isolation verdict `"host"`;
exit code `0`.

The working tree also contained local-only audit evidence. The validator's
security scan emitted two `caution` warnings for test-token examples in those
untracked files:

```text
security scan caution: hardcoded_secret
  (AUDIT_HANDOVER_2026-11-11.md:383),\n  (evidence/live_2026-11-11/README.md:85)
```

Those files are excluded from the public commit. Validate the clean tracked tree
before catalog submission. A clean export of the tracked index (80 files at
that point) was validated separately:

```text
"ok": true
15 checks, all true
"warnings": []
"isolation": { "verdict": "host", "host_ready": true, "reasons": [] }
exit 0
```

The two warnings therefore came only from untracked local evidence. The final
81-file tree was rechecked: 15/15 checks, `warnings: []`, exit `0`.

The catalog CI command is:

```powershell
hermes plugins validate <repository> --json --install-deps
```

An `--install-deps` attempt on the audit host was started but did not complete
within a 600-second window. It reached:

```text
→ Resolving Python dependencies…
✓ Resolving Python dependencies
→ Installing Python dependencies…
```

and was stopped by the command timeout. No dependency-install pass is claimed.
See [Known verification gaps](#known-verification-gaps). The plain validator
(capability probe, manifest, registration, security, isolation) passed.

**Status: VERIFIED for the plain validator; `--install-deps` UNKNOWN on this
host.**

### 3. Host-mediated `continuum_status` tool turn

A fresh Hermes turn used the real host tool registry and the production plugin:

```powershell
$env:OPENAI_BASE_URL = 'http://127.0.0.1:<fixture-port>/v1'
$env:OPENAI_API_KEY = '<local-test-placeholder>'
& $H -p continuum-live -z "CALL_TOOL:continuum_status_direct -- call the Continuum status tool directly and report the result."
```

The command exited `0` and printed:

```text
Hermes Continuum live direct tool turn completed.
```

The Event Spine recorded:

| Field | Value |
|---|---|
| Event ID | `2105` |
| Event type | `tool_result_observed` |
| Summary | `continuum_status ok in 81 ms` |
| Session | `20261111_141515_5a4ff7` |
| Tool call ID | `call_14` |
| Result length | `1795` |

A following event `2108` was `subgoal.advanced`. The event count advanced from
`2096` to `2110` after the turn, and later reads showed `2,112` and `2,115` as
the checkpoint and API work completed. The Timeline screenshot shows the
`continuum_status ok in 81 ms` row under the `continuum-live` profile.

The fixture's bridge-style marker `CALL_TOOL:continuum_status` produced
`Model generated invalid tool call: tool_call`; it is **not** claimed as a
working path. The direct marker above is the verified one.

**Status: VERIFIED for the direct host tool turn and Event Spine record.**

### 4. Production Desktop Console

The production Electron app was launched from the pinned host checkout and
connected to a manually started, isolated backend on `127.0.0.1:52750`. The
profile selector was set to `continuum-live`. The production plugin's Desktop
surface was enabled under **Capabilities → Plugins**.

Visible results:

- **Overview:** `gateway open`, `profile continuum-live`, live event count,
  recent `checkpoint_exported` activity.
- **Timeline:** `Event Spine`, `continuum_status ok in 81 ms`,
  `tool_result_observed`, session `20261111_141515_5a4ff7`.
- **Security & Checkpoints:** `gateway open`, `Backend ready`,
  `ENCRYPTED CHECKPOINTS`, `2 records · 1 file`, file
  `continuum-20261111-101410-62576ef4.hcc`, `local file`, `3300 KB`.
- The earlier six-view audit also rendered Overview, Nine Systems, Forge,
  Timeline, Memory, and Security & Checkpoints with live `continuum-live` data.

Screenshots are in [docs/screenshots/](docs/screenshots/):

- `continuum-timeline-fresh.png`
- `continuum-security-fresh.png`
- `continuum-security-checkpoints-fresh.png`

The screenshots are captures of the production Desktop, not static mockups.
They are supporting evidence for the live session; the Event Spine row and the
checkpoint file are the primary observations.

**Status: VERIFIED for the six views and the fresh Timeline/Security captures.**

A normal one-click Desktop launch on the audit host was blocked by the host's
interrupted source update. The verified path used a temporary local launcher
that imported the real `hermes_cli.main` while bypassing only the bootstrap's
source-update completion. It did not modify the host checkout or the
`.hermes-update-in-progress` marker. This is a host-environment workaround, not
a plugin feature.

### 5. Dashboard API reads

All 15 GET routes under `/api/plugins/hermes-continuum/` returned HTTP `200` on
the live backend: `/health`, `/status`, `/overview`, `/timeline`,
`/events/{event_id}`, `/memory`, `/security`, `/checkpoints`, `/pillars`,
`/reality`, `/evidence`, `/charters`, `/previews`, `/execution`, and `/forge`.

The live `/status` response reported:

```text
plugin: hermes-continuum, version 0.3.0, schema_version 3
events: 2112
checkpoints: 1
playbooks: 1
active_leases: 1
```

**Status: VERIFIED for the 15 GET routes.**

### 6. Live checkpoint export (mutation)

One authenticated mutation was exercised through the production Dashboard API:

```text
POST /api/plugins/hermes-continuum/checkpoints/export
```

The request supplied a random passphrase in the request body. The response
created:

| Field | Value |
|---|---|
| Record | `ckpt_045ede84e9d44ec898aaf76d62576ef4` |
| File | `continuum-20261111-101410-62576ef4.hcc` |
| SHA-256 | `af6544b846a24a308cc8cd629f5c26d1f1dca6ee8077aa0c67de08dce5355fec` |
| Location | the plugin checkpoint directory |
| Desktop display | `2 records · 1 file`, `local file`, `3300 KB` |

The raw export response contains a full environment fingerprint with local
paths. It is retained only as local audit evidence and is not reproduced here.

A prior checkpoint record `ckpt_3a76ea4486634e5ca59d4de3f486a9d2` exists but
points at `checkpoints.hcc` one level above the configured checkpoint directory;
it is visible as a record but not as a listed file. The second export is the
correctly listed file.

**Status: VERIFIED for checkpoint export through the production API and
Desktop file listing.**

### 7. Offline formal suite

The original host-enabled full offline run for this build was:

```text
185 passed, 1 warning in 506.25s (0:08:26)
```

The warning is a third-party Starlette/httpx `TestClient` deprecation warning,
not a plugin failure.

After the live audit, the only submission edit to the tests was removing a
hardcoded local Hermes launcher path from `tests/test_installation.py`. The
installed-host validator smoke test is now opt-in via `HERMES_LAUNCHER`; without
it the test skips. The submission-tree rerun produced:

```text
184 passed, 1 skipped, 1 warning in 163.00s (0:02:42)
```

A targeted rerun of the edited installation file produced:

```text
8 passed, 1 skipped in 12.50s
```

The plugin implementation was not changed for submission preparation.

**Status: VERIFIED for the offline suite and the test-harness portability
edit.**

## Live vs. offline matrix

| Capability | Status | Evidence |
|---|---|---|
| Plugin load in isolated profile | **VERIFIED** | Profile load and 12/11 doctor output |
| `continuum_status` host tool call | **VERIFIED** | Event `2105`, session `20261111_141515_5a4ff7` |
| Event Spine writes and Timeline read | **VERIFIED** | Timeline screenshot and live API |
| Production Desktop six views | **VERIFIED** | Screenshots and rendered text |
| 15 Dashboard GET routes | **VERIFIED** | HTTP 200 for every route |
| Checkpoint export via Dashboard API | **VERIFIED** | Record `ckpt_045ede...`, listed file |
| Plain plugin validator | **VERIFIED** | 15/15 checks, exit 0 |
| Validator `--install-deps` | **UNKNOWN** | Timed out at dependency install |
| Memory review, dream, recall | **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Offline suite |
| Evidence, charter, preview, execution reset | **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Offline suite |
| Forge, playbook, lease issue/revoke | **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Offline suite; historical live artifacts exist |
| Quarantine consumption | **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Offline suite |
| Checkpoint inspect/import | **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Offline suite |
| Retention and Attack Lab mutations | **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Offline suite |
| Cron lease enforcement | **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Deterministic hook tests and historical Cron evidence, no fresh Cron run |
| Tool-scope block and live revocation | **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Offline suite |
| Fresh-process skill/blueprint rehydration | **IMPLEMENTED BUT NOT LIVE-VERIFIED** | Offline suite |
| Normal one-click Desktop launch | **UNKNOWN on audit host** | Blocked by host update marker |
| `on_session_finalize` return-message behaviour | **UNKNOWN** | Not used |
| Rollback/undo of external actions | **NOT IMPLEMENTED** | Deliberate scope boundary |
| Perfect prompt-injection protection | **NOT IMPLEMENTED** | Deliberate scope boundary |

## Known verification gaps

1. `--install-deps` did not finish on the audit host within 600 seconds. The
   dependency install step must be completed in CI or on a clean host before
   claiming catalog-admission parity.
2. The model was a disclosed local fixture. Replace it with a production model
   for a public performance claim; the tool call, plugin, spine, and Desktop are
   already real.
3. The normal Desktop launcher is blocked by the host's interrupted source
   update. The manual remote-gateway path is verified, but a one-click launch is
   not.
4. Only one mutation route has live evidence. The other 26 Dashboard mutation
   routes are covered by the offline TestClient suite.
5. A real Hermes Cron job was not executed in this verification pass. Historical
   Cron evidence exists but is not a fresh run for this exact build.
6. Live tool-scope enforcement, lease revocation, quarantine consumption,
   checkpoint import, and fresh-process rehydration remain unverified.

## Reproduction notes

All commands run from the repository root unless noted. Set:

```powershell
$H = "$env:LOCALAPPDATA\hermes\bin\hermes.cmd"
$plugin = (Resolve-Path .).Path
```

The live Desktop path also needs a running isolated backend and the production
Electron app. The exact host-specific launcher workaround is intentionally a
local runbook, not part of the public plugin. Do not edit or delete
`.hermes-update-in-progress`.

The local-only audit evidence, including raw API payloads, historical reports,
machine paths, and the full-size checkpoint database, is retained in the
developer workspace but is not part of the public commit. The public tree
contains only the plugin, tests, current docs, and the selected live
screenshots.
