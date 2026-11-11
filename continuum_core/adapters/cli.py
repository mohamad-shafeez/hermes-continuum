"""CLI and slash-command adapters for Hermes Continuum.

The CLI is the secret-safe checkpoint door: passphrases are read with
``getpass`` (or one line from stdin via ``--passphrase-stdin``) and never appear
in argv.  Slash commands intentionally expose only non-secret operations.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Any, Callable

from ..checkpoint import MIN_PASSPHRASE_LENGTH
from ..common.errors import CheckpointError, ContinuumError, StorageError
from ..common.redaction import truncate
from ..tripwire import run_attack_lab

ServiceFactory = Callable[[], Any]

_MAX_ERROR_CHARS = 500


def _json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _error(code: str, message: str) -> str:
    return _json(
        {
            "ok": False,
            "error": code,
            "message": truncate(message, _MAX_ERROR_CHARS),
        }
    )


def _safe_message(exc: BaseException) -> str:
    if isinstance(exc, (CheckpointError, StorageError, ContinuumError)):
        return str(exc)
    return f"{type(exc).__name__}: operation failed."


def _print(payload: Any) -> None:
    print(_json(payload), flush=True)


def _read_passphrase(*, from_stdin: bool, confirm: bool) -> str:
    if from_stdin:
        line = sys.stdin.readline()
        if not line:
            raise CheckpointError("No passphrase was provided on stdin.")
        value = line.rstrip("\r\n")
    else:
        if not sys.stdin.isatty():
            raise CheckpointError(
                "No interactive terminal is available. Use --passphrase-stdin."
            )
        value = getpass.getpass("Checkpoint passphrase: ")
        if confirm:
            again = getpass.getpass("Confirm passphrase: ")
            if again != value:
                raise CheckpointError("The passphrases did not match.")
    if len(value) < MIN_PASSPHRASE_LENGTH:
        raise CheckpointError(
            f"The passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters."
        )
    return value


def _confirm(prompt: str, *, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    answer = input(f"{prompt} [y/N] ").strip().lower()
    return answer in {"y", "yes"}


# ---------------------------------------------------------------------------
# argparse setup
# ---------------------------------------------------------------------------
def setup_cli(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="action", metavar="<action>")

    sub.add_parser("status", help="Show Continuum status and counts.")
    sub.add_parser("overview", help="Show the Console overview payload.")
    sub.add_parser("config", help="Show the effective Continuum configuration.")
    sub.add_parser("doctor", help="Run local storage, policy, and crypto checks.")

    timeline = sub.add_parser("timeline", help="List Event Spine records.")
    timeline.add_argument("--limit", type=int, default=50)
    timeline.add_argument("--type", dest="event_type", default=None)
    timeline.add_argument("--module", default=None)
    timeline.add_argument("--session", dest="session_id", default=None)
    timeline.add_argument("--search", default=None)
    timeline.add_argument("--before-id", dest="before_id", type=int, default=None)

    memory = sub.add_parser("memory", help="Review Oneiros memory facts.")
    memory_sub = memory.add_subparsers(dest="memory_action", metavar="<action>")
    memory_list = memory_sub.add_parser("list", help="List memory facts.")
    memory_list.add_argument("--status", default=None)
    memory_list.add_argument("--query", default=None)
    memory_list.add_argument("--limit", type=int, default=50)
    for name, help_text in (
        ("confirm", "Confirm a candidate fact."),
        ("reject", "Reject a candidate fact."),
    ):
        item = memory_sub.add_parser(name, help=help_text)
        item.add_argument("fact_id")
    edit = memory_sub.add_parser("edit", help="Edit a fact's value (new version).")
    edit.add_argument("fact_id")
    edit.add_argument("value", nargs="*")
    edit.add_argument(
        "--value",
        dest="value_option",
        nargs="+",
        default=None,
        help="Compatibility form: the replacement value.",
    )
    forget = memory_sub.add_parser("forget", help="Permanently delete a fact.")
    forget.add_argument("fact_id")
    forget.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")

    sub.add_parser("dream", help="Run Oneiros consolidation now.")
    recall = sub.add_parser("recall", help="Search confirmed and candidate memory.")
    recall.add_argument("query", nargs="+")
    recall.add_argument("--limit", type=int, default=5)
    attack_lab = sub.add_parser("attack-lab", help="Run a deterministic Attack Lab suite.")
    attack_lab.add_argument(
        "--suite",
        choices=("tripwire", "hephaestus"),
        default="tripwire",
        help="Which fixed suite to run (default tripwire).",
    )

    checkpoint = sub.add_parser("checkpoint", help="Manage encrypted checkpoints.")
    checkpoint_sub = checkpoint.add_subparsers(
        dest="checkpoint_action", metavar="<action>"
    )
    checkpoint_sub.add_parser("list", help="List checkpoint records and files.")
    export = checkpoint_sub.add_parser("export", help="Export an encrypted checkpoint.")
    export.add_argument("--out", default=None, help="Destination file or directory.")
    export.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="Read the passphrase from one stdin line instead of prompting.",
    )
    inspect = checkpoint_sub.add_parser("inspect", help="Decrypt and preview a checkpoint.")
    inspect.add_argument("path")
    inspect.add_argument("--checksum", default=None)
    inspect.add_argument("--passphrase-stdin", action="store_true")
    import_cmd = checkpoint_sub.add_parser("import", help="Preview and import a checkpoint.")
    import_cmd.add_argument("path")
    import_cmd.add_argument("--checksum", default=None)
    import_cmd.add_argument("--passphrase-stdin", action="store_true")
    import_cmd.add_argument(
        "--yes",
        "--confirm",
        dest="yes",
        action="store_true",
        help="Apply after preview.",
    )

    retention = sub.add_parser("retention", help="Apply the episode retention window.")
    retention.add_argument("--days", type=int, default=None)
    retention.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")

    resume = sub.add_parser("resume", help="Show or dismiss the active resume brief.")
    resume_sub = resume.add_subparsers(dest="resume_action", metavar="<action>")
    resume_sub.add_parser("show", help="Show the active resume brief.")
    resume_dismiss = resume_sub.add_parser("dismiss", help="Dismiss a resume brief.")
    resume_dismiss.add_argument("brief_id")

    reality = sub.add_parser("reality", help="Inspect Kairos environment snapshots and diffs.")
    reality_sub = reality.add_subparsers(dest="reality_action", metavar="<action>")
    reality_sub.add_parser("list", help="List environment snapshots and diffs.")
    reality_snapshot = reality_sub.add_parser("snapshot", help="Fingerprint a scoped environment.")
    reality_snapshot.add_argument("--scope", default=None)
    reality_snapshot.add_argument("--label", default="")
    reality_snapshot.add_argument("--path", dest="paths", action="append", default=[])
    reality_diff = reality_sub.add_parser("diff", help="Diff the current environment.")
    reality_diff.add_argument("snapshot_id", nargs="?", default=None)

    evidence = sub.add_parser("evidence", help="Inspect Aletheia evidence receipts.")
    evidence_sub = evidence.add_subparsers(dest="evidence_action", metavar="<action>")
    evidence_list = evidence_sub.add_parser("list", help="List receipts and protected work.")
    evidence_list.add_argument("--artifact", default=None)
    evidence_list.add_argument("--status", default=None)
    evidence_list.add_argument("--limit", type=int, default=50)
    evidence_show = evidence_sub.add_parser("show", help="Show one receipt.")
    evidence_show.add_argument("receipt_id")
    evidence_record = evidence_sub.add_parser("record-file", help="Hash a local file as evidence.")
    evidence_record.add_argument("path")
    evidence_record.add_argument("--expected-sha256", default=None)
    evidence_record.add_argument("--scope", default="")
    evidence_record.add_argument("--memory-ref", default=None)
    evidence_confirm = evidence_sub.add_parser("confirm", help="Confirm an evidence receipt.")
    evidence_confirm.add_argument("receipt_id")
    evidence_confirm.add_argument("--yes", action="store_true")
    evidence_protect = evidence_sub.add_parser("protect", help="Protect an artifact from silent mutation.")
    evidence_protect.add_argument("artifact_ref")
    evidence_protect.add_argument("--receipt-id", default=None)
    evidence_protect.add_argument("--scope", default="")
    evidence_protect.add_argument("--yes", action="store_true")
    evidence_release = evidence_sub.add_parser("release", help="Release protected work.")
    evidence_release.add_argument("protected_id")
    evidence_release.add_argument("--reason", default="")
    evidence_release.add_argument("--yes", action="store_true")
    evidence_sub.add_parser("challenges", help="List protected-artifact challenges.")

    charter = sub.add_parser("charter", help="Inspect or amend Telos task charters.")
    charter_sub = charter.add_subparsers(dest="charter_action", metavar="<action>")
    charter_sub.add_parser("list", help="List charters, amendments, drift, and completions.")
    charter_show = charter_sub.add_parser("show", help="Show one charter or the active charter.")
    charter_show.add_argument("charter_id", nargs="?", default=None)
    charter_show.add_argument("--session", dest="session_id", default=None)
    charter_active = charter_sub.add_parser("active", help="Show the active charter.")
    charter_active.add_argument("--session", dest="session_id", default=None)
    charter_amend = charter_sub.add_parser("amend", help="Amend a charter on explicit user request.")
    charter_amend.add_argument("charter_id")
    charter_amend.add_argument("amendment", nargs="+")
    charter_amend.add_argument("--rationale", default="")
    charter_amend.add_argument("--yes", action="store_true")
    charter_complete = charter_sub.add_parser("complete", help="Score completion honestly.")
    charter_complete.add_argument("charter_id")
    charter_complete.add_argument("--evidence", dest="evidence_ids", action="append", default=[])
    charter_complete.add_argument("--yes", action="store_true")
    charter_advance = charter_sub.add_parser("advance", help="Update a subgoal's completion state.")
    charter_advance.add_argument("charter_id")
    charter_advance.add_argument("subgoal_id")
    charter_advance.add_argument("--completed", action="store_true")

    preview = sub.add_parser("preview", help="Preview a proposed action without executing it.")
    preview_sub = preview.add_subparsers(dest="preview_action", metavar="<action>")
    preview_sub.add_parser("list", help="List recent impact previews.")
    preview_run = preview_sub.add_parser("run", help="Preview one proposed tool call.")
    preview_run.add_argument("tool_name")
    preview_run.add_argument("--args-json", default="{}")
    preview_run.add_argument("--session", dest="session_id", default=None)

    execution = sub.add_parser("execution", help="Inspect or reset Metis retry circuits.")
    execution_sub = execution.add_subparsers(dest="execution_action", metavar="<action>")
    execution_sub.add_parser("list", help="List failure fingerprints and circuits.")
    execution_status = execution_sub.add_parser("status", help="Show one circuit.")
    execution_status.add_argument("circuit_id")
    execution_reset = execution_sub.add_parser("reset", help="Close a retry circuit.")
    execution_reset.add_argument("circuit_id")
    execution_reset.add_argument("--reason", default="Reset by user")
    execution_reset.add_argument("--yes", action="store_true")

    playbook = sub.add_parser("playbook", help="Review Hephaestus forged playbooks.")
    playbook_sub = playbook.add_subparsers(dest="playbook_action", metavar="<action>")
    playbook_list = playbook_sub.add_parser("list", help="List forged playbooks.")
    playbook_list.add_argument("--status", default=None)
    playbook_show = playbook_sub.add_parser("show", help="Show one playbook.")
    playbook_show.add_argument("playbook_id")
    playbook_distill = playbook_sub.add_parser("distill", help="Analyze a session trace.")
    playbook_distill.add_argument("session_id")
    playbook_quarantine = playbook_sub.add_parser("quarantine", help="Quarantine a playbook.")
    playbook_quarantine.add_argument("playbook_id")
    playbook_quarantine.add_argument("--reason", default="Quarantined by user")
    playbook_quarantine.add_argument("--yes", action="store_true")
    playbook_unquarantine = playbook_sub.add_parser(
        "unquarantine", help="Lift a playbook quarantine."
    )
    playbook_unquarantine.add_argument("playbook_id")
    playbook_unquarantine.add_argument("--yes", action="store_true")

    forge = sub.add_parser("forge", help="Distill a trace into a skill and blueprint.")
    forge.add_argument("session_id")
    forge.add_argument("--name", default="")
    forge.add_argument("--description", default="")
    forge.add_argument("--schedule", default="0 9 * * *")
    forge.add_argument("--allowed-tool", dest="allowed_tools", action="append", default=[])
    forge.add_argument("--allowed-path", dest="allowed_paths", action="append", default=[])
    forge.add_argument("--allowed-domain", dest="allowed_domains", action="append", default=[])
    forge.add_argument("--allow-opaque-tools", action="store_true")
    forge.add_argument("--max-tool-calls", type=int, default=None)
    forge.add_argument("--max-file-writes", type=int, default=None)
    forge.add_argument("--max-external-calls", type=int, default=None)
    forge.add_argument("--ttl-minutes", type=int, default=None)
    forge.add_argument("--expires-at", default=None)
    forge.add_argument("--cron-job-id", default=None)
    forge.add_argument("--allow-untrusted", action="store_true")
    forge.add_argument("--force", action="store_true")
    forge.add_argument("--no-lease", action="store_true", help="Forge without issuing a lease.")
    forge.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")

    lease = sub.add_parser("lease", help="Review and manage Hephaestus safety leases.")
    lease_sub = lease.add_subparsers(dest="lease_action", metavar="<action>")
    lease_list = lease_sub.add_parser("list", help="List leases and per-run usage.")
    lease_list.add_argument("--status", default=None)
    lease_list.add_argument("--playbook", dest="playbook_id", default=None)
    lease_issue = lease_sub.add_parser("issue", help="Issue a bounded safety lease.")
    lease_issue.add_argument("playbook_id")
    lease_issue.add_argument("--allowed-tool", dest="allowed_tools", action="append", default=[])
    lease_issue.add_argument("--allowed-path", dest="allowed_paths", action="append", default=[])
    lease_issue.add_argument("--allowed-domain", dest="allowed_domains", action="append", default=[])
    lease_issue.add_argument("--allow-opaque-tools", action="store_true")
    lease_issue.add_argument("--max-tool-calls", type=int, default=None)
    lease_issue.add_argument("--max-file-writes", type=int, default=None)
    lease_issue.add_argument("--max-external-calls", type=int, default=None)
    lease_issue.add_argument("--ttl-minutes", type=int, default=None)
    lease_issue.add_argument("--expires-at", default=None)
    lease_issue.add_argument("--cron-job-id", default=None)
    lease_issue.add_argument("--yes", action="store_true")
    lease_revoke = lease_sub.add_parser("revoke", help="Revoke a safety lease.")
    lease_revoke.add_argument("lease_id")
    lease_revoke.add_argument("--reason", default="Revoked by user")
    lease_revoke.add_argument("--yes", action="store_true")
    for name, help_text in (
        ("quarantine", "Quarantine a playbook and revoke its lease."),
        ("unquarantine", "Lift a playbook quarantine."),
    ):
        item = lease_sub.add_parser(name, help=help_text)
        item.add_argument("playbook_id")
        item.add_argument("--reason", default="Quarantined by user")
        item.add_argument("--yes", action="store_true")


# ---------------------------------------------------------------------------
# CLI handler
# ---------------------------------------------------------------------------
def _dispatch(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.action or "status"
    if action == "status":
        return service.status()
    if action == "overview":
        return service.overview()
    if action == "config":
        return {
            "ok": True,
            "config": service.config_dict(),
            "checkpoint_dir": str(service.checkpoint_service.checkpoint_dir),
        }
    if action == "timeline":
        return {
            "ok": True,
            "events": service.timeline(
                limit=args.limit,
                event_type=args.event_type,
                module=args.module,
                session_id=args.session_id,
                search=args.search,
                before_id=args.before_id,
            ),
        }
    if action == "memory":
        return _dispatch_memory(service, args)
    if action == "dream":
        return {"ok": True, "dream": service.dream()}
    if action == "recall":
        query = " ".join(args.query).strip()
        if not query:
            return {
                "ok": False,
                "error": "invalid_query",
                "message": "A non-empty query is required.",
            }
        limit = max(1, min(50, args.limit))
        facts = service.recall(query, limit=limit)
        return {
            "ok": True,
            "query": query,
            "count": len(facts),
            "facts": facts,
            "note": (
                "Facts marked candidate are unverified proposals and must not "
                "be treated as established."
            ),
        }
    if action == "attack-lab":
        return service.run_attack_lab(suite=getattr(args, "suite", "tripwire"))
    if action == "checkpoint":
        return _dispatch_checkpoint(service, args)
    if action == "reality":
        return _dispatch_reality(service, args)
    if action == "evidence":
        return _dispatch_evidence(service, args)
    if action == "charter":
        return _dispatch_charter(service, args)
    if action == "preview":
        return _dispatch_preview(service, args)
    if action == "execution":
        return _dispatch_execution(service, args)
    if action == "playbook":
        return _dispatch_playbook(service, args)
    if action == "forge":
        return _dispatch_forge(service, args)
    if action == "lease":
        return _dispatch_lease(service, args)
    if action == "resume":
        resume_action = args.resume_action or "show"
        if resume_action == "show":
            return {"ok": True, "brief": service.active_resume_brief()}
        if resume_action == "dismiss":
            service.dismiss_resume_brief(args.brief_id)
            return {"ok": True, "dismissed": args.brief_id}
        return {
            "ok": False,
            "error": "invalid_action",
            "message": f"Unknown resume action: {resume_action}",
        }
    if action == "retention":
        days = (
            args.days
            if args.days is not None
            else service.config.episode_retention_days
        )
        if not _confirm(
            f"Delete episodes older than {days} days?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Retention cancelled. Re-run with --yes to confirm.",
            }
        return {"ok": True, "retention": service.apply_retention(args.days)}
    if action == "doctor":
        return _doctor(service)
    return {"ok": False, "error": "invalid_action", "message": f"Unknown action: {action}"}


def _dispatch_memory(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.memory_action or "list"
    if action == "list":
        allowed = {"candidate", "confirmed", "rejected", "superseded", "contradicted"}
        if args.status is not None and args.status not in allowed:
            return {
                "ok": False,
                "error": "invalid_status",
                "message": (
                    "`--status` must be candidate, confirmed, rejected, "
                    "superseded, or contradicted."
                ),
            }
        facts = service.memory_list(status=args.status, query=args.query)
        return {
            "ok": True,
            "counts": service.memory_counts(),
            "facts": facts[: max(1, min(500, args.limit))],
        }
    if action == "confirm":
        return {"ok": True, "fact": service.confirm_memory(args.fact_id)}
    if action == "reject":
        return {"ok": True, "fact": service.reject_memory(args.fact_id)}
    if action == "edit":
        parts = args.value_option if args.value_option is not None else args.value
        value = " ".join(parts).strip()
        if not value:
            return {"ok": False, "error": "invalid_value", "message": "A value is required."}
        return {"ok": True, "fact": service.edit_memory(args.fact_id, value=value)}
    if action == "forget":
        if not _confirm(
            f"Permanently delete memory fact {args.fact_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Deletion cancelled. Re-run with --yes to confirm.",
            }
        return {"ok": True, "deleted": service.forget_memory(args.fact_id)}
    return {"ok": False, "error": "invalid_action", "message": f"Unknown memory action: {action}"}


def _dispatch_checkpoint(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.checkpoint_action or "list"
    if action == "list":
        return {
            "ok": True,
            "checkpoint_dir": str(service.checkpoint_service.checkpoint_dir),
            "records": service.list_checkpoints(),
            "files": service.checkpoint_files(),
        }
    if action == "export":
        passphrase = _read_passphrase(
            from_stdin=args.passphrase_stdin, confirm=True
        )
        destination = Path(args.out).expanduser() if args.out else None
        return service.export_checkpoint(passphrase, destination=destination)
    if action == "inspect":
        passphrase = _read_passphrase(
            from_stdin=args.passphrase_stdin, confirm=False
        )
        return service.inspect_checkpoint(
            args.path, passphrase, expected_checksum=args.checksum
        )
    if action == "import":
        passphrase = _read_passphrase(
            from_stdin=args.passphrase_stdin, confirm=False
        )
        preview = service.import_checkpoint(
            args.path,
            passphrase,
            confirm=False,
            expected_checksum=args.checksum,
        )
        if not _confirm("Import this checkpoint into Continuum?", assume_yes=args.yes):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Import cancelled after preview. Re-run with --yes to apply.",
                "preview": preview,
            }
        return service.import_checkpoint(
            args.path,
            passphrase,
            confirm=True,
            expected_checksum=args.checksum,
        )
    return {
        "ok": False,
        "error": "invalid_action",
        "message": f"Unknown checkpoint action: {action}",
    }


def _dispatch_reality(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.reality_action or "list"
    if action == "list":
        return service.reality()
    if action == "snapshot":
        return {
            "ok": True,
            "snapshot": service.reality_snapshot(
                scope=args.scope,
                paths=args.paths,
                label=args.label,
            ),
        }
    if action == "diff":
        return {
            "ok": True,
            "diff": service.reality_diff(args.snapshot_id),
        }
    return {"ok": False, "error": "invalid_action", "message": f"Unknown reality action: {action}"}


def _dispatch_evidence(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.evidence_action or "list"
    if action == "list":
        receipts = service.aletheia.list_receipts(
            artifact_ref=args.artifact,
            status=args.status,
            limit=max(1, min(100, args.limit)),
        )
        return {
            "ok": True,
            "receipts": receipts,
            "protected": service.aletheia.list_protected(limit=100),
            "challenges": service.aletheia.list_challenges(limit=100),
        }
    if action == "show":
        receipt = service.aletheia.get_receipt(args.receipt_id)
        if receipt is None:
            return {"ok": False, "error": "not_found", "message": "Evidence receipt not found."}
        return {"ok": True, "receipt": receipt}
    if action == "record-file":
        return {
            "ok": True,
            "receipt": service.record_evidence_file(
                args.path,
                expected_sha256=args.expected_sha256,
                scope=args.scope,
                memory_ref=args.memory_ref,
            ),
        }
    if action == "confirm":
        if not _confirm(
            f"Confirm evidence receipt {args.receipt_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Confirmation cancelled. Re-run with --yes to confirm.",
            }
        return {"ok": True, "receipt": service.confirm_evidence(args.receipt_id)}
    if action == "protect":
        if not _confirm(
            f"Protect {args.artifact_ref} from silent mutation?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Protection cancelled. Re-run with --yes to confirm.",
            }
        return {
            "ok": True,
            "protected": service.protect_artifact(
                args.artifact_ref, receipt_id=args.receipt_id, scope=args.scope
            ),
        }
    if action == "release":
        if not _confirm(
            f"Release protected artifact {args.protected_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Release cancelled. Re-run with --yes to confirm.",
            }
        return {
            "ok": True,
            "protected": service.release_artifact(
                args.protected_id, reason=args.reason
            ),
        }
    if action == "challenges":
        return {"ok": True, "challenges": service.aletheia.list_challenges(limit=100)}
    return {"ok": False, "error": "invalid_action", "message": f"Unknown evidence action: {action}"}


def _dispatch_charter(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.charter_action or "active"
    if action == "list":
        return service.charters()
    if action == "active":
        return {
            "ok": True,
            "charter": service.telos.active_charter(session_id=args.session_id),
        }
    if action == "show":
        charter = (
            service.telos.get_charter(args.charter_id)
            if args.charter_id
            else service.telos.active_charter(session_id=args.session_id)
        )
        if charter is None:
            return {"ok": False, "error": "not_found", "message": "No matching charter."}
        return {
            "ok": True,
            "charter": charter,
            "context": service.telos.context(charter),
        }
    if action == "amend":
        if not _confirm(
            f"Amend charter {args.charter_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Amendment cancelled. Re-run with --yes to confirm.",
            }
        amendment = " ".join(args.amendment).strip()
        if not amendment:
            return {"ok": False, "error": "invalid_amendment", "message": "An amendment is required."}
        return {
            "ok": True,
            "charter": service.amend_charter(
                args.charter_id,
                amendment,
                rationale=args.rationale,
                confirmed=True,
            ),
        }
    if action == "complete":
        if not _confirm(
            f"Score completion for charter {args.charter_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Completion scoring cancelled. Re-run with --yes to confirm.",
            }
        return {
            "ok": True,
            "assessment": service.assess_completion(
                args.charter_id,
                claimed_complete=True,
                evidence_ids=args.evidence_ids,
                user_confirmed=True,
            ),
        }
    if action == "advance":
        return {
            "ok": True,
            "charter": service.telos.advance_subgoal(
                args.charter_id,
                subgoal_id=args.subgoal_id,
                completed=args.completed,
            ),
        }
    return {"ok": False, "error": "invalid_action", "message": f"Unknown charter action: {action}"}


def _dispatch_preview(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.preview_action or "list"
    if action == "list":
        return service.previews()
    if action == "run":
        try:
            proposed_args = json.loads(args.args_json)
        except ValueError:
            return {
                "ok": False,
                "error": "invalid_args",
                "message": "`--args-json` must be a JSON object.",
            }
        if not isinstance(proposed_args, dict):
            return {
                "ok": False,
                "error": "invalid_args",
                "message": "`--args-json` must be a JSON object.",
            }
        return {
            "ok": True,
            "preview": service.preview_action(
                args.tool_name,
                proposed_args,
                session_id=args.session_id,
            ),
            "note": "Preview only. Nothing was executed.",
        }
    return {"ok": False, "error": "invalid_action", "message": f"Unknown preview action: {action}"}


def _dispatch_execution(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.execution_action or "list"
    if action == "list":
        return service.execution()
    if action == "status":
        circuit = service.metis.get_circuit(args.circuit_id)
        if circuit is None:
            return {"ok": False, "error": "not_found", "message": "Metis circuit not found."}
        return {"ok": True, "circuit": circuit}
    if action == "reset":
        if not _confirm(
            f"Reset Metis circuit {args.circuit_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Reset cancelled. Re-run with --yes to confirm.",
            }
        return {
            "ok": True,
            "circuit": service.reset_circuit(args.circuit_id, reason=args.reason),
        }
    return {"ok": False, "error": "invalid_action", "message": f"Unknown execution action: {action}"}


def _dispatch_playbook(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.playbook_action or "list"
    if action == "list":
        return {
            "ok": True,
            "playbooks": service.hephaestus.list_playbooks(status=args.status),
            "counts": service.store.hephaestus_counts(),
        }
    if action == "show":
        playbook = service.hephaestus.playbook(args.playbook_id)
        if playbook is None:
            return {"ok": False, "error": "not_found", "message": "Playbook not found."}
        return {"ok": True, "playbook": playbook}
    if action == "distill":
        return {
            "ok": True,
            "trace": service.distill_trace(args.session_id),
            "note": "Read-only trace analysis. No artifact or lease was created.",
        }
    if action == "quarantine":
        if not _confirm(
            f"Quarantine playbook {args.playbook_id} and revoke its lease?",
            assume_yes=args.yes,
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Quarantine cancelled. Re-run with --yes to confirm.",
            }
        return {
            "ok": True,
            "playbook": service.quarantine_playbook(
                args.playbook_id, reason=args.reason, confirmed=True
            ),
        }
    if action == "unquarantine":
        if not _confirm(
            f"Lift quarantine for playbook {args.playbook_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Unquarantine cancelled. Re-run with --yes to confirm.",
            }
        return {
            "ok": True,
            "playbook": service.unquarantine_playbook(args.playbook_id, confirmed=True),
        }
    return {"ok": False, "error": "invalid_action", "message": f"Unknown playbook action: {action}"}


def _forge_options(args: argparse.Namespace) -> dict[str, Any]:
    options: dict[str, Any] = {
        "name": args.name,
        "description": args.description,
        "schedule": args.schedule,
        "allowed_tools": args.allowed_tools or None,
        "allowed_paths": args.allowed_paths or None,
        "allowed_domains": args.allowed_domains or None,
        "allow_opaque_tools": bool(args.allow_opaque_tools),
        "max_tool_calls": args.max_tool_calls,
        "max_file_writes": args.max_file_writes,
        "max_external_calls": args.max_external_calls,
        "ttl_minutes": args.ttl_minutes,
        "expires_at": args.expires_at,
        "cron_job_id": args.cron_job_id,
        "allow_untrusted": bool(args.allow_untrusted),
        "force": bool(args.force),
    }
    return {key: value for key, value in options.items() if value is not None}


def _dispatch_forge(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    preview = service.preview_forge(args.session_id, **_forge_options(args))
    if not args.yes:
        return {
            "ok": True,
            "status": "preview",
            "can_forge": preview.get("can_forge"),
            "warnings": preview.get("warnings"),
            "playbook": preview.get("playbook"),
            "lease": preview.get("lease"),
            "message": "No artifact was forged. Re-run with --yes to confirm.",
        }
    result = service.forge_playbook(
        args.session_id,
        confirm=True,
        issue_lease=not args.no_lease,
        **_forge_options(args),
    )
    return {"ok": True, **result}


def _dispatch_lease(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    action = args.lease_action or "list"
    if action == "list":
        return {
            "ok": True,
            "leases": service.store.list_safety_leases(
                playbook_id=args.playbook_id, status=args.status, limit=200
            ),
            "usage": service.store.list_lease_usage(limit=100),
            "counts": service.store.hephaestus_counts(),
        }
    if action == "issue":
        if not _confirm(
            f"Issue a safety lease for playbook {args.playbook_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Lease issue cancelled. Re-run with --yes to confirm.",
            }
        return {
            "ok": True,
            "lease": service.issue_lease(
                args.playbook_id,
                allowed_tools=args.allowed_tools or None,
                allowed_paths=args.allowed_paths or None,
                allowed_domains=args.allowed_domains or None,
                allow_opaque_tools=bool(args.allow_opaque_tools),
                max_tool_calls=args.max_tool_calls,
                max_file_writes=args.max_file_writes,
                max_external_calls=args.max_external_calls,
                ttl_minutes=args.ttl_minutes,
                expires_at=args.expires_at,
                cron_job_id=args.cron_job_id,
                confirmed=True,
            ),
        }
    if action == "revoke":
        if not _confirm(
            f"Revoke lease {args.lease_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": "Lease revocation cancelled. Re-run with --yes to confirm.",
            }
        return {
            "ok": True,
            "lease": service.revoke_lease(args.lease_id, reason=args.reason, confirmed=True),
        }
    if action in {"quarantine", "unquarantine"}:
        if not _confirm(
            f"{action.title()} playbook {args.playbook_id}?", assume_yes=args.yes
        ):
            return {
                "ok": False,
                "error": "confirmation_required",
                "message": f"{action.title()} cancelled. Re-run with --yes to confirm.",
            }
        if action == "quarantine":
            return {
                "ok": True,
                "playbook": service.quarantine_playbook(
                    args.playbook_id, reason=args.reason, confirmed=True
                ),
            }
        return {
            "ok": True,
            "playbook": service.unquarantine_playbook(args.playbook_id, confirmed=True),
        }
    return {"ok": False, "error": "invalid_action", "message": f"Unknown lease action: {action}"}


def _doctor(service: Any) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": truncate(detail, 300)})

    try:
        status = service.status()
        add(
            "storage",
            True,
            f"schema {status['schema_version']}, {status['stats']['events']} events, "
            f"database {service.store.database_path or 'unknown'}",
        )
    except Exception as exc:  # noqa: BLE001
        add("storage", False, _safe_message(exc))

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        del AESGCM, Scrypt
        add("crypto", True, "AES-256-GCM and scrypt are available.")
    except Exception as exc:  # noqa: BLE001
        add(
            "crypto",
            False,
            f"Safe checkpoint encryption is unavailable ({type(exc).__name__}); "
            "checkpoint export/import will fail closed.",
        )

    try:
        directory = Path(service.checkpoint_service.checkpoint_dir)
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".continuum-doctor-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        add("checkpoint_dir", True, f"writable: {directory}")
    except Exception as exc:  # noqa: BLE001
        add("checkpoint_dir", False, _safe_message(exc))

    try:
        results = run_attack_lab()
        passed = sum(1 for item in results if item.get("passed"))
        add("attack_lab", passed == len(results), f"{passed}/{len(results)} synthetic cases passed.")
    except Exception as exc:  # noqa: BLE001
        add("attack_lab", False, _safe_message(exc))

    try:
        path = str(service.store.database_path or "")
        normalized = path.replace("\\", "/")
        ok = True
        detail = f"database path: {path}"
        if "plugin-data" in normalized:
            detail = "database lives under plugin-data."
        try:
            from hermes_constants import get_hermes_home

            private = str(Path(get_hermes_home()) / "sessions").replace("\\", "/")
            if normalized.startswith(private):
                ok = False
                detail = f"database is inside Hermes private session storage: {path}"
        except Exception:
            # Outside a Hermes process there is no private-storage root to compare.
            pass
        add("data_isolation", ok, detail)
    except Exception as exc:  # noqa: BLE001
        add("data_isolation", False, _safe_message(exc))

    return {"ok": all(item["ok"] for item in checks), "checks": checks}


def run_cli(args: argparse.Namespace, service_factory: ServiceFactory) -> int:
    service = None
    try:
        service = service_factory()
        payload = _dispatch(service, args)
    except Exception as exc:  # noqa: BLE001
        payload = {
            "ok": False,
            "error": "operation_failed",
            "message": _safe_message(exc),
        }
    finally:
        if service is not None:
            try:
                service.close()
            except Exception:
                pass
    _print(payload)
    return 0 if payload.get("ok", True) else 1


def register_cli(ctx: Any, service_factory: ServiceFactory) -> None:
    def handler(args: argparse.Namespace) -> int:
        return run_cli(args, service_factory)

    ctx.register_cli_command(
        name="continuum",
        help="Continuum status, memory, security, checkpoints, and eight-system state",
        setup_fn=setup_cli,
        handler_fn=handler,
        description=(
            "Inspect the Event Spine, review Oneiros memory, run consolidation, "
            "run the Attack Lab, manage encrypted checkpoints, and inspect or act "
            "on Kairos, Aletheia, Telos, Moirai, and Metis state."
        ),
    )


# ---------------------------------------------------------------------------
# Slash command
# ---------------------------------------------------------------------------
_SLASH_HELP = """Continuum commands:
  /continuum status
  /continuum pillars
  /continuum recall <query>
  /continuum memory [list [candidate|confirmed] | confirm <id> | reject <id> | edit <id> <value> | forget <id> --yes]
  /continuum dream
  /continuum attack-lab [--suite tripwire|hephaestus]
  /continuum checkpoint
  /continuum reality [diff]
  /continuum evidence [list]
  /continuum charter [active|list]
  /continuum preview [list]
  /continuum execution [list]
  /continuum playbook [list|show <id>]
  /continuum lease [list]
  /forge list | /forge <session_id> [--yes]
Checkpoint export/import, evidence confirmation, charter amendments, circuit resets, forging, and lease issue/revoke use `hermes continuum ...` or the Continuum Console; passphrases are never accepted in chat."""


def _format_fact(fact: dict[str, Any]) -> str:
    status = str(fact.get("status") or "unknown")
    key = str(fact.get("fact_key") or "fact")
    value = truncate(str(fact.get("value") or ""), 220)
    provenance = truncate(str(fact.get("provenance") or ""), 120)
    suffix = f" — {provenance}" if provenance else ""
    return f"- [{status}] {key}: {value}{suffix}"


def build_slash_handler(service_factory: ServiceFactory) -> Callable[[str], str]:
    def handler(raw_args: str) -> str:
        tokens = str(raw_args or "").strip().split()
        if not tokens:
            tokens = ["status"]
        command = tokens[0].lower()
        rest = tokens[1:]
        if command in {"help", "?"}:
            return _SLASH_HELP
        service = None
        try:
            service = service_factory()
            if command == "status":
                status = service.status()
                counts = status["stats"]
                memory = status["memory_counts"]
                last = status.get("last_event_at") or "never"
                return (
                    f"Continuum v{status['version']} · schema {status['schema_version']} · "
                    f"policy {status['policy_version']}\n"
                    f"Events {counts.get('events', 0)} · sources {counts.get('sources', 0)} · "
                    f"episodes {counts.get('episodes', 0)} · "
                    f"facts {counts.get('memory_facts', 0)} · "
                    f"decisions {counts.get('security_decisions', 0)} · "
                    f"checkpoints {counts.get('checkpoints', 0)}\n"
                    f"Memory: {memory.get('confirmed', 0)} confirmed, "
                    f"{memory.get('candidate', 0)} pending review. Last event: {last}"
                )
            if command == "recall":
                query = " ".join(rest).strip()
                if not query:
                    return "Usage: /continuum recall <query>"
                facts = service.recall(query, limit=8)
                if not facts:
                    return "No matching Continuum memory."
                return "Continuum recall:\n" + "\n".join(_format_fact(fact) for fact in facts)
            if command == "memory":
                return _slash_memory(service, rest)
            if command == "dream":
                result = service.dream()
                report = result.get("report") or {}
                return (
                    f"Oneiros consolidation {result.get('status', 'completed')}: "
                    f"{result.get('episodes_processed', 0)} episodes, "
                    f"{result.get('candidates_created', 0)} candidates, "
                    f"{len(result.get('contradictions') or [])} contradictions. "
                    f"Review with /continuum memory list candidate."
                )
            if command in {"attack-lab", "attack_lab", "lab"}:
                suite = "tripwire"
                if rest and rest[0].lower() == "--suite" and len(rest) >= 2:
                    suite = rest[1].lower()
                result = service.run_attack_lab(suite=suite)
                return (
                    f"Attack Lab ({result['suite']}): {result['passed']}/{result['total']} "
                    f"deterministic cases passed (policy {result['run']['policy_version']}). "
                    "Synthetic cases only; not a guarantee of prompt-injection immunity."
                )
            if command == "checkpoint":
                records = service.list_checkpoints()
                files = service.checkpoint_files()
                return (
                    f"Checkpoints: {len(records)} record(s), {len(files)} file(s) in "
                    f"{service.checkpoint_service.checkpoint_dir}. "
                    "Export/import with `hermes continuum checkpoint ...` or the Continuum Console."
                )
            if command == "pillars":
                payload = service.pillars()
                lines = ["Continuum pillars:"]
                for pillar in payload.get("pillars") or []:
                    metrics = pillar.get("metrics") or {}
                    rendered = ", ".join(f"{key}={value}" for key, value in metrics.items())
                    lines.append(
                        f"- {pillar.get('name')} ({' + '.join(pillar.get('systems') or [])}): {rendered}"
                    )
                return "\n".join(lines)
            if command == "reality":
                if len(rest) >= 1 and rest[0].lower() == "diff":
                    diff = service.reality_diff()
                    return (
                        f"Reality {diff.get('level')}: {diff.get('summary')} "
                        f"({len(diff.get('changed') or [])} observed change(s), "
                        f"{len(diff.get('unverified') or [])} unverified)."
                    )
                payload = service.reality()
                latest = payload.get("latest_snapshot") or {}
                diffs = payload.get("diffs") or []
                return (
                    f"Kairos: {len(payload.get('snapshots') or [])} snapshot(s), "
                    f"{len(diffs)} diff(s). Latest: "
                    f"{latest.get('fingerprint_hash', 'none')[:16]} "
                    f"at {latest.get('captured_at') or 'never'}."
                )
            if command == "evidence":
                receipts = service.aletheia.list_receipts(limit=10)
                protected = service.aletheia.list_protected(limit=10)
                current = sum(1 for item in receipts if item.get("status") == "current")
                return (
                    f"Aletheia: {current} current receipt(s) shown, "
                    f"{len(protected)} protection record(s). "
                    "Confirm/protect/release with `hermes continuum evidence ...`."
                )
            if command == "charter":
                action = rest[0].lower() if rest else "active"
                if action == "list":
                    payload = service.charters()
                    return (
                        f"Telos: {len(payload.get('charters') or [])} charter(s), "
                        f"{len(payload.get('amendments') or [])} amendment(s), "
                        f"{len(payload.get('drift') or [])} drift observation(s), "
                        f"{len(payload.get('completions') or [])} completion score(s)."
                    )
                charter = (
                    service.telos.get_charter(rest[1])
                    if action == "show" and len(rest) >= 2
                    else service.telos.active_charter()
                )
                if charter is None:
                    return "No active Telos charter."
                return service.telos.context(charter)
            if command == "preview":
                previews = (service.previews().get("previews") or [])[:5]
                if not previews:
                    return "No Moirai impact previews yet."
                return "Moirai previews:\n" + "\n".join(
                    f"- {item.get('level')}: {truncate(str(item.get('proposed_action') or ''), 180)}"
                    for item in previews
                )
            if command == "execution":
                payload = service.execution()
                circuits = payload.get("circuits") or []
                open_circuits = [item for item in circuits if item.get("status") == "open"]
                if not open_circuits:
                    return (
                        f"Metis: no open circuits; "
                        f"{len(payload.get('failures') or [])} failure observation(s)."
                    )
                return "Metis open circuits:\n" + "\n".join(
                    f"- {item.get('tool_name')}: {truncate(str(item.get('reason') or ''), 180)} "
                    f"(expires {item.get('expires_at')})"
                    for item in open_circuits[:10]
                )
            if command == "playbook":
                action = rest[0].lower() if rest else "list"
                if action == "show" and len(rest) >= 2:
                    playbook = service.hephaestus.playbook(rest[1])
                    if playbook is None:
                        return "Hephaestus playbook not found."
                    return (
                        f"{playbook.get('name')} ({playbook.get('status')})\n"
                        f"confidence {int(round(float(playbook.get('confidence') or 0) * 100))}% · "
                        f"steps {playbook.get('steps_succeeded')}/{playbook.get('steps_attempted')} · "
                        f"lease {playbook.get('lease_id') or 'none'}\n"
                        f"skill: {playbook.get('skill_path') or 'not written'}"
                    )
                playbooks = service.hephaestus.list_playbooks()[:10]
                if not playbooks:
                    return "No Hephaestus playbooks forged yet. Use /forge <session_id>."
                return "Hephaestus playbooks:\n" + "\n".join(
                    f"- {item.get('slug')} [{item.get('status')}] "
                    f"{item.get('confidence_percent')}% confidence"
                    for item in playbooks
                )
            if command == "lease":
                leases = service.store.list_safety_leases(limit=10)
                usage = service.store.list_lease_usage(limit=10)
                if not leases:
                    return "No Hephaestus safety leases. Forge a playbook or issue a lease in the Console."
                return (
                    f"Hephaestus leases: {len(leases)} shown, {len(usage)} run usage row(s).\n"
                    + "\n".join(
                        f"- {item.get('id')} [{item.get('status')}] "
                        f"expires {item.get('expires_at') or 'never'} · "
                        f"tools {len(item.get('allowed_tools') or [])}"
                        for item in leases
                    )
                )
            return _SLASH_HELP
        except Exception as exc:  # noqa: BLE001
            return f"Continuum unavailable: {_safe_message(exc)}"
        finally:
            if service is not None:
                try:
                    service.close()
                except Exception:
                    pass

    return handler


def _slash_memory(service: Any, rest: list[str]) -> str:
    action = rest[0].lower() if rest else "list"
    if action == "list":
        status = rest[1].lower() if len(rest) > 1 else "candidate"
        if status not in {"candidate", "confirmed", "rejected", "superseded", "contradicted"}:
            return (
                "Status must be candidate, confirmed, rejected, superseded, "
                "or contradicted."
            )
        facts = service.memory_list(status=status)[:10]
        counts = service.memory_counts()
        if not facts:
            return (
                f"No {status} memory facts. "
                f"Counts: {counts.get('confirmed', 0)} confirmed, "
                f"{counts.get('candidate', 0)} pending."
            )
        header = (
            f"{status.title()} memory ({len(facts)} shown; "
            f"{counts.get('candidate', 0)} pending review):"
        )
        return header + "\n" + "\n".join(_format_fact(fact) for fact in facts)
    if action == "confirm" and len(rest) >= 2:
        fact = service.confirm_memory(rest[1])
        return f"Confirmed {fact['fact_key']}: {truncate(fact['value'], 220)}"
    if action == "reject" and len(rest) >= 2:
        fact = service.reject_memory(rest[1])
        return f"Rejected {fact['fact_key']}."
    if action == "edit" and len(rest) >= 3:
        fact = service.edit_memory(rest[1], value=" ".join(rest[2:]))
        return f"Edited {fact['fact_key']} as version {fact.get('version')}."
    if action == "forget" and len(rest) >= 3 and rest[2] == "--yes":
        service.forget_memory(rest[1])
        return f"Deleted memory fact {rest[1]}."
    return _SLASH_HELP


_FORGE_HELP = """Hephaestus forging:
  /forge list
  /forge <session_id>            Preview the trace, skill, blueprint, and lease.
  /forge <session_id> --yes      Write artifacts and issue the default lease.
Forging requires an explicit user request. Use `hermes continuum forge ...` or the
Continuum Console for tools, paths, domains, budgets, expiry, or a Cron job id."""


def build_forge_slash_handler(service_factory: ServiceFactory) -> Callable[[str], str]:
    """A narrow slash entry point: preview by default, write only with --yes."""

    def handler(raw_args: str) -> str:
        tokens = str(raw_args or "").strip().split()
        if not tokens or tokens[0].lower() in {"help", "?"}:
            return _FORGE_HELP
        service = None
        try:
            service = service_factory()
            if tokens[0].lower() == "list":
                playbooks = service.hephaestus.list_playbooks()[:10]
                if not playbooks:
                    return "No Hephaestus playbooks forged yet."
                return "Hephaestus playbooks:\n" + "\n".join(
                    f"- {item.get('slug')} [{item.get('status')}] "
                    f"{item.get('confidence_percent')}% confidence"
                    for item in playbooks
                )
            session_id = tokens[0]
            confirmed = "--yes" in tokens[1:]
            if not confirmed:
                preview = service.preview_forge(session_id)
                warnings = preview.get("warnings") or []
                return (
                    f"Forge preview for session {session_id}: "
                    f"{preview.get('playbook', {}).get('confidence_percent')}% confidence, "
                    f"{preview.get('playbook', {}).get('steps_succeeded')}/"
                    f"{preview.get('playbook', {}).get('steps_attempted')} steps, "
                    f"can_forge={preview.get('can_forge')}.\n"
                    + ("Warnings: " + " ".join(str(item) for item in warnings[:3]) + "\n" if warnings else "")
                    + "No artifact was written. Re-run with --yes to confirm."
                )
            result = service.forge_playbook(session_id, confirm=True)
            return (
                f"Hephaestus forged {result.get('playbook', {}).get('slug')} "
                f"({result.get('status')}). Skill: "
                f"{result.get('skill', {}).get('path')}. Lease: "
                f"{(result.get('lease') or {}).get('id') or 'none'}. "
                "Review it in the Continuum Console before unattended use."
            )
        except Exception as exc:  # noqa: BLE001
            return f"Hephaestus unavailable: {_safe_message(exc)}"
        finally:
            if service is not None:
                try:
                    service.close()
                except Exception:
                    pass

    return handler
