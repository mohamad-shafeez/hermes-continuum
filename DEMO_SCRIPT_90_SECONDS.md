# Hermes Continuum - 90-second live demo

**Target:** Hermes Agent `v0.22.2`, commit
`d923a5eb487a17c0a68801bba9ef0f56c81040a8`, isolated profile `continuum-live`.

**Plugin:** `hermes-continuum` `0.3.0`.

**Primary proof:** a fresh host-mediated `continuum_status` tool call followed by
its Event Spine row in the production Hermes Desktop Console.

**Supporting proof:** a live encrypted checkpoint export through the production
Dashboard API and the Desktop Security view.

The setup below is done before recording. The demo clock starts when the
Timeline is already open in the production Desktop Console.

## What the audience must understand

- The host tool registry, plugin, Event Spine, Dashboard API, and Desktop are
  real Hermes surfaces.
- The recorded model is a local deterministic OpenAI-compatible fixture. It is
  disclosed on screen; it is not a production model and is not claimed as one.
- The demo does not claim that all nine systems are live-verified. The live
  subset is the status tool, the Event Spine, the Desktop read views, the 15 GET
  API routes, and checkpoint export.
- A real checkpoint import, Cron run, lease revocation, quarantine consumption,
  tool-scope block, and fresh-process rehydration are not shown as live.

## Pre-record setup (not counted in the demo clock)

Run from the repository root in a PowerShell window.

```powershell
$H = "$env:LOCALAPPDATA\hermes\bin\hermes.cmd"
$profile = "continuum-live"
$plugin = (Resolve-Path .).Path
```

Preflight:

```powershell
& $H -p $profile plugins doctor $plugin --ci
```

Expected:

```text
OK: runtime discovery, manifest parsing, import, and registration passed
registrations: 12 tool(s), 11 hook(s)
```

Start the isolated backend in its own PowerShell window:

```powershell
$env:HERMES_DASHBOARD_SESSION_TOKEN = "<random-local-token>"
& $H -p $profile serve --port 52750 --skip-build --isolated
```

Wait for the backend-ready line, then start the production Electron app with a
temporary user-data directory. In the app:

1. **Gateway settings → Remote gateway**:
   `http://127.0.0.1:52750`, session token `<random-local-token>`, then
   **Save and reconnect**.
2. **Capabilities → Plugins**: enable **Desktop: Continuum**.
3. Select the **`continuum-live`** profile in the profile selector, not
   `default`.
4. Open **Continuum → Timeline**.

If the normal launcher reports `source-update completion failed: an update is
still running`, the host has an interrupted source update. Do not edit or delete
`.hermes-update-in-progress`. Use the local audit launcher documented in
`SUBMISSION_CHECKLIST.md`; it imports the real CLI and only stubs the
source-update completion step.

Start the disclosed local model fixture in a third PowerShell window if it is
not already running:

```powershell
$env:OPENAI_BASE_URL = "http://127.0.0.1:8765/v1"
$env:OPENAI_API_KEY = "<local-test-placeholder>"
```

The fixture is a test model, not a product model. A production OpenAI-compatible
provider can replace it for the same tool call.

## The timed run (under 90 seconds)

| Time | Action | Expected visible result |
|---|---|---|
| 0:00-0:08 | Open **Continuum → Timeline** in the production Desktop. Select **`continuum-live`**. | Header shows `gateway open`, `profile continuum-live`, plugin `v0.3.0`. |
| 0:08-0:12 | Point at the existing Timeline row `continuum_status ok in 81 ms`, type `tool_result_observed`, session `20261111_141515_5a4ff7`. | The row expands or highlights; the summary and session are visible. This is the stored proof from the fresh tool turn. |
| 0:12-0:16 | Switch to the backend PowerShell window and state: "Now a new host-mediated call, not a replay." | Terminal prompt is visible. |
| 0:16-0:36 | Run: `& $H -p continuum-live -z "CALL_TOOL:continuum_status_direct -- call the Continuum status tool directly and report the result."` | Exit `0`; output `Hermes Continuum live direct tool turn completed.` The model fixture requests the real tool. |
| 0:36-0:49 | Return to Desktop. Click **Refresh** if the Timeline is not already updating. | A new `tool_result_observed` row appears with a new event ID and summary `continuum_status ok in <n> ms`; the clock time is current. |
| 0:49-1:06 | Open **Security & Checkpoints**. Use the Console export form with a random passphrase. | A new encrypted checkpoint record appears. The section shows `ENCRYPTED CHECKPOINTS`, a recent count such as `2 records · 1 file`, the `.hcc` filename, `local file`, and the size. |
| 1:06-1:14 | Show the pre-run doctor output: 12 tools, 11 hooks. | Terminal/console text: `registrations: 12 tool(s), 11 hook(s)`. |
| 1:14-1:23 | State the boundary in one sentence. | "Live: status tool, Event Spine, Desktop views, and checkpoint export. Not shown live: import, Cron, lease revocation, quarantine, rehydration, and the other mutation routes." |

Total: **83 seconds**, with about 7 seconds of buffer under the 90-second cap.
If the checkpoint export takes longer than the allotted window, skip the export
and end on the fresh Timeline event; do not replace it with a static screenshot.

## Exact tool-turn command

```powershell
$env:OPENAI_BASE_URL = "http://127.0.0.1:8765/v1"
$env:OPENAI_API_KEY = "<local-test-placeholder>"
& $H -p continuum-live -z "CALL_TOOL:continuum_status_direct -- call the Continuum status tool directly and report the result."
```

The recorded run produced:

```text
Hermes Continuum live direct tool turn completed.
```

The Event Spine recorded event `2105`, `tool_result_observed`, summary
`continuum_status ok in 81 ms`, session `20261111_141515_5a4ff7`, tool call
`call_14`. A new run will produce a new event ID and a new duration; do not read
the old 81 ms as a constant.

The bridge marker `CALL_TOOL:continuum_status` is not used. On the recorded
profile it returned `Model generated invalid tool call: tool_call`. The direct
marker is the verified path.

## Exact checkpoint export path

The production Desktop calls:

```text
POST /api/plugins/hermes-continuum/checkpoints/export
```

with a random passphrase in the request body. The Console drops the passphrase
after the call. The recorded live export created record
`ckpt_045ede84e9d44ec898aaf76d62576ef4` and file
`continuum-20261111-101410-62576ef4.hcc`, listed in the Desktop as a local file.

Do not display the raw API response: it contains a full environment fingerprint
with local paths.

## Live versus UI-only or architecture-only

**Live in the demo**

- Host-mediated `continuum_status` call through the real tool registry.
- Event Spine write and Timeline read.
- Production Desktop Console rendering the `continuum-live` profile.
- 15 GET Dashboard API routes (pre-verified; not all shown on camera).
- Checkpoint export through the production Dashboard mutation route and the
  resulting encrypted file listing.

**UI-only in the demo**

- The Nine Systems, Forge, Memory, and other cards are read models. Showing a
  card is not proof that its mutation path was exercised.
- The profile selector and remote gateway are Desktop controls, not plugin
  features.

**Implemented and test-covered, but not live-verified in this demo**

- Memory review, dream consolidation, recall.
- Evidence receipts and protected work.
- Telos charters and completion scoring.
- Moirai previews, Metis circuit reset.
- Forge preview/confirmation, playbook quarantine, lease issue/revoke.
- Checkpoint inspect/import and resume brief.
- Retention, Attack Lab runs, and the remaining 26 Dashboard mutation routes.
- Cron lease enforcement, live tool-scope blocks, live revocation, quarantine
  consumption, and fresh-process skill/blueprint rehydration.

**Do not say**

- "All nine systems are live-verified."
- "This is a production model run."
- "The normal one-click Desktop launch works on this host."
- "Checkpoint import was verified live."
- "Every Dashboard mutation route was exercised."
- "The Attack Lab proves prompt-injection immunity."

## Fallback if the live tool turn fails

1. Do not stage a fake tool result or a pre-recorded screenshot as live proof.
2. Keep the existing Timeline row and explain that it is stored live evidence
   from the recorded session, then show the `plugins doctor` output and the
   checkpoint file.
3. If the backend is down, stop the demo and state the host blocker. The
   screenshots in `docs/screenshots/` are supporting evidence, not a substitute
   for a live run.
