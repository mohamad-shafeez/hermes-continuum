"""Aletheia: evidence receipts and protection for verified work.

A receipt records what was actually checked and how.  It is not a claim that a
saved document is factually correct, that a command's exit code proves an
outcome, or that a test run with zero tests is meaningful.  Protection is a
challenge layer, never an immutability guarantee: an authorised user can always
release or change their own work.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from ..common.config import ContinuumConfig
from ..common.ids import new_id, stable_hash
from ..common.redaction import redact_mapping, redact_text, truncate
from ..common.time import utc_now_iso
from ..spine.store import SpineStore

_VERIFIED_STATUSES = {"current", "stale"}
_FAILURE_TEXT = re.compile(r"(?i)\b(?:fail(?:ed|ure|ing)?|error|traceback|exception)\b")
_NO_TESTS = re.compile(
    r"(?i)(?:no\s+tests?|0\s+tests?|0\s+passed|collected\s+0|ran\s+0|"
    r"0\s+selected|no\s+test\s+ran|nothing\s+to\s+test)"
)
_TEST_COUNT = re.compile(
    r"(?i)(?P<count>\d+)\s+(?:passed|tests?\s+passed|test[s]?\s+collected|collected)"
)
_DESTRUCTIVE_COMMAND = re.compile(
    r"(?i)\b(?:rm|del|erase|rmdir|mv|move|cp|copy|rename|truncate|shred|"
    r"set-content|add-content|out-file|tee|write|drop|alter|delete|update|insert|"
    r"upload|send|post|put|patch)\b"
)
_DESTRUCTIVE_TOOLS = re.compile(
    r"(?i)^(?:write|patch|delete|remove|move|rename|replace|truncate|upload|send|"
    r"post|put|update|execute|terminal|shell|database|db_|api_|http_|webhook|deploy|publish)"
)


class AletheiaService:
    def __init__(
        self,
        store: SpineStore,
        config: ContinuumConfig | None = None,
        *,
        kairos: Any = None,
    ):
        self.store = store
        self.config = (config or ContinuumConfig()).clamped()
        self.kairos = kairos

    # ------------------------------------------------------------------
    # Receipts
    # ------------------------------------------------------------------
    def record_receipt(
        self,
        *,
        artifact_ref: str,
        artifact_type: str = "artifact",
        verification_method: str,
        observed_result: str = "",
        scope: str = "",
        content_hash: str | None = None,
        expected_hash: str | None = None,
        environment_snapshot: dict[str, Any] | None = None,
        source_ref: str | None = None,
        trust_label: str = "PLUGIN_GENERATED",
        provenance: str = "PLUGIN_GENERATED",
        memory_ref: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        artifact_ref = redact_text(str(artifact_ref or "").strip(), max_chars=1000)
        if not artifact_ref:
            raise ValueError("An artifact reference is required.")
        method = redact_text(str(verification_method or "").strip(), max_chars=120)
        if not method:
            raise ValueError("A verification method is required.")
        verified, status, reason = _assess_evidence(
            method,
            observed_result,
            content_hash=content_hash,
            expected_hash=expected_hash,
            user_confirmed=user_confirmed,
        )
        status = status if status in {"current", "stale", "unverified", "superseded", "rejected"} else "unverified"
        receipt_id = new_id("evd")
        env_hash = None
        env_snapshot_id = None
        if environment_snapshot:
            env_hash = environment_snapshot.get("fingerprint_hash")
            env_snapshot_id = environment_snapshot.get("id")
        receipt_body = {
            "reason": reason,
            "expected_hash_present": bool(expected_hash),
            "user_confirmed": bool(user_confirmed),
            "method": method,
            "limitations": _limitations(method),
        }
        event_type = "evidence.recorded" if status != "rejected" else "evidence.rejected"
        event_id = self.store.append_event(
            event_type,
            f"Evidence {status}: {truncate(_display_ref(artifact_ref), 180)}",
            session_id=session_id,
            task_id=task_id,
            source_ref=source_ref,
            trust_label=trust_label,
            memory_ref=memory_ref,
            details={
                "receipt_id": receipt_id,
                "artifact_ref": _display_ref(artifact_ref),
                "method": method,
                "status": status,
                "verified": verified,
                "reason": reason,
                "environment_hash": env_hash,
            },
            idempotency_key=None,
        )
        receipt = self.store.record_evidence_receipt(
            receipt_id=receipt_id,
            event_id=event_id,
            artifact_ref=artifact_ref,
            artifact_type=artifact_type,
            verification_method=method,
            observed_result=observed_result,
            scope=scope,
            content_hash=content_hash,
            environment_hash=env_hash,
            environment_snapshot_id=env_snapshot_id,
            source_ref=source_ref,
            trust_label=trust_label,
            provenance=provenance,
            verified=verified,
            status=status,
            receipt=receipt_body,
            memory_ref=memory_ref,
            session_id=session_id,
            task_id=task_id,
        )
        if verified and memory_ref:
            self.store.set_fact_evidence(memory_ref, receipt_id)
        return receipt

    def verify_file(
        self,
        path: Path | str,
        *,
        expected_sha256: str | None = None,
        artifact_type: str = "file",
        scope: str = "",
        environment_snapshot: dict[str, Any] | None = None,
        memory_ref: str | None = None,
        source_ref: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        max_bytes: int = 64 * 1024 * 1024,
    ) -> dict[str, Any]:
        target = Path(path).expanduser()
        if not target.is_file():
            raise ValueError("The file to verify does not exist.")
        try:
            size = target.stat().st_size
        except OSError as exc:
            raise ValueError(f"The file could not be inspected: {type(exc).__name__}") from exc
        if size > max_bytes:
            raise ValueError("The file is larger than the evidence verification limit.")
        digest = _sha256_file(target)
        matched = True
        if expected_sha256:
            matched = hmac.compare_digest(digest.lower(), expected_sha256.lower())
        observed = f"sha256={digest}; size={size} bytes"
        if expected_sha256 and not matched:
            observed += "; expected hash did not match"
            status = "rejected"
            verified = False
        else:
            status = "current"
            verified = True
        receipt = self.record_receipt(
            artifact_ref=str(target.resolve()),
            artifact_type=artifact_type,
            verification_method="file_sha256",
            observed_result=observed,
            scope=scope or "content integrity (the file's bytes at verification time)",
            content_hash=digest,
            expected_hash=expected_sha256,
            environment_snapshot=environment_snapshot,
            source_ref=source_ref,
            memory_ref=memory_ref,
            session_id=session_id,
            task_id=task_id,
            trust_label="LOCAL_TOOL_OUTPUT",
            provenance="LOCAL_TOOL_OUTPUT",
        )
        # ``record_receipt`` recomputes the assessment; preserve a mismatch's
        # rejected status even though the observed bytes are authentic.
        if not verified and receipt.get("status") != "rejected":
            receipt = self.store.update_evidence_receipt(
                receipt["id"], status="rejected", verified=False
            ) or receipt
        if memory_ref and verified:
            self.store.set_fact_evidence(memory_ref, receipt["id"])
        return receipt

    def confirm_receipt(
        self, receipt_id: str, *, confirmed_by: str = "user"
    ) -> dict[str, Any]:
        receipt = self.store.get_evidence_receipt(receipt_id)
        if receipt is None:
            raise ValueError("Evidence receipt not found.")
        if receipt.get("status") == "rejected":
            raise ValueError("Rejected evidence cannot be confirmed without a new verification.")
        updated = self.store.update_evidence_receipt(
            receipt_id, status="current", verified=True
        )
        if updated is None:
            raise ValueError("Evidence receipt not found.")
        self.store.append_event(
            "evidence.confirmed",
            f"Evidence confirmed by {confirmed_by}: {truncate(_display_ref(str(receipt.get('artifact_ref'))), 180)}",
            source_ref=receipt.get("source_ref"),
            trust_label="USER_AUTHORED",
            memory_ref=receipt.get("memory_ref"),
            details={
                "receipt_id": receipt_id,
                "confirmed_by": redact_text(confirmed_by, max_chars=80),
                "artifact_ref": _display_ref(str(receipt.get("artifact_ref") or "")),
            },
            idempotency_key=f"evidence-confirmed:{receipt_id}",
        )
        if receipt.get("memory_ref"):
            self.store.set_fact_evidence(str(receipt["memory_ref"]), receipt_id)
        return updated

    def stale_for_environment(
        self, environment_hash: str, *, reason: str
    ) -> list[dict[str, Any]]:
        receipts = self.store.stale_evidence_for_environment(
            environment_hash, reason=reason
        )
        for receipt in receipts:
            self.store.append_event(
                "evidence.staled",
                f"Evidence stale after environment change: {truncate(_display_ref(str(receipt.get('artifact_ref'))), 180)}",
                source_ref=receipt.get("source_ref"),
                trust_label=receipt.get("trust_label"),
                memory_ref=receipt.get("memory_ref"),
                details={
                    "receipt_id": receipt.get("id"),
                    "artifact_ref": _display_ref(str(receipt.get("artifact_ref") or "")),
                    "reason": truncate(reason, 500),
                },
                idempotency_key=f"evidence-staled:{receipt.get('id')}:{environment_hash}",
            )
            if receipt.get("memory_ref"):
                fact = self.store.mark_fact_reverification(
                    str(receipt["memory_ref"]),
                    reason=reason,
                    evidence_ref=str(receipt.get("id") or ""),
                )
                if fact is not None:
                    self.store.append_event(
                        "memory.reverification_required",
                        "Memory requires re-verification after environmental change",
                        memory_ref=str(receipt["memory_ref"]),
                        trust_label=receipt.get("trust_label"),
                        details={
                            "fact_id": receipt["memory_ref"],
                            "evidence_ref": receipt.get("id"),
                            "reason": truncate(reason, 500),
                        },
                        idempotency_key=f"memory-reverify:{receipt.get('memory_ref')}:{environment_hash}",
                    )
        return receipts

    def list_receipts(
        self, *, artifact_ref: str | None = None, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        return self.store.list_evidence_receipts(
            artifact_ref=artifact_ref, status=status, limit=limit
        )

    def get_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        return self.store.get_evidence_receipt(receipt_id)

    # ------------------------------------------------------------------
    # Protection and challenge handling
    # ------------------------------------------------------------------
    def protect(
        self,
        artifact_ref: str,
        *,
        receipt_id: str | None = None,
        artifact_type: str = "file",
        scope: str = "",
        confirmed_by: str = "user",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        artifact_ref = redact_text(str(artifact_ref or "").strip(), max_chars=1000)
        if not artifact_ref:
            raise ValueError("An artifact reference is required.")
        receipt = self.store.get_evidence_receipt(receipt_id) if receipt_id else None
        if receipt_id and receipt is None:
            raise ValueError("Evidence receipt not found.")
        if receipt is None:
            candidates = [
                item
                for item in self.store.list_evidence_receipts(artifact_ref=artifact_ref, limit=20)
                if item.get("verified") and item.get("status") in _VERIFIED_STATUSES
            ]
            receipt = candidates[0] if candidates else None
        if receipt is None or not receipt.get("verified"):
            raise ValueError(
                "Protection requires a verified evidence receipt for this artifact."
            )
        protected = self.store.protect_artifact(
            protected_id=new_id("prot"),
            artifact_ref=artifact_ref,
            artifact_type=artifact_type,
            receipt_id=str(receipt["id"]),
            scope=scope,
            metadata={"confirmed_by": confirmed_by, **(metadata or {})},
        )
        if protected is None:
            raise ValueError("The artifact could not be protected.")
        self.store.append_event(
            "work.protected",
            f"Protected work: {truncate(_display_ref(artifact_ref), 180)}",
            source_ref=receipt.get("source_ref"),
            trust_label="USER_AUTHORED",
            memory_ref=receipt.get("memory_ref"),
            details={
                "protected_id": protected.get("id"),
                "receipt_id": receipt.get("id"),
                "artifact_ref": _display_ref(artifact_ref),
                "scope": truncate(scope, 300),
            },
            idempotency_key=f"work-protected:{protected.get('id')}",
        )
        return protected

    def release(
        self, protected_id: str, *, reason: str = "", confirmed_by: str = "user"
    ) -> dict[str, Any]:
        protected = self.store.get_protected_artifact(protected_id)
        if protected is None:
            raise ValueError("Protected artifact not found.")
        updated = self.store.release_protected_artifact(protected_id, reason=reason)
        if updated is None:
            raise ValueError("Protected artifact not found.")
        self.store.append_event(
            "work.released",
            f"Released protection: {truncate(_display_ref(str(protected.get('artifact_ref'))), 180)}",
            trust_label="USER_AUTHORED",
            details={
                "protected_id": protected_id,
                "artifact_ref": _display_ref(str(protected.get("artifact_ref") or "")),
                "reason": truncate(reason, 500),
                "confirmed_by": redact_text(confirmed_by, max_chars=80),
            },
            idempotency_key=f"work-released:{protected_id}",
        )
        return updated

    def challenges_for_action(
        self,
        tool_name: str,
        args: Any,
        *,
        action_ref: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        source_ref: str | None = None,
        trust_label: str = "UNKNOWN",
    ) -> list[dict[str, Any]]:
        if not _is_destructive(tool_name, args):
            return []
        text = _action_text(args)
        action_key = action_ref or stable_hash(
            {"tool": tool_name, "args": _safe_action_text(args)}
        )
        existing_challenges = self.store.list_evidence_challenges(limit=500)
        challenges: list[dict[str, Any]] = []
        for protected in self.store.list_protected_artifacts(limit=500):
            if not protected.get("active"):
                continue
            ref = str(protected.get("artifact_ref") or "")
            if not _reference_matches(ref, text):
                continue
            receipt = (
                self.store.get_evidence_receipt(str(protected.get("receipt_id")))
                if protected.get("receipt_id")
                else None
            )
            duplicate = next(
                (
                    item
                    for item in existing_challenges
                    if item.get("action_ref") == action_key
                    and item.get("protected_id") == str(protected.get("id"))
                    and item.get("status") == "held"
                ),
                None,
            )
            if duplicate is not None:
                duplicate["evidence"] = receipt
                challenges.append(duplicate)
                continue
            evidence_summary = _evidence_summary(receipt)
            reason = (
                f"The proposed action targets protected work: {_display_ref(ref)}. "
                f"{evidence_summary} A host-approved change or new verified evidence "
                "is required before this protection is released."
            )
            challenge = self.store.record_evidence_challenge(
                challenge_id=new_id("chal"),
                artifact_ref=ref,
                protected_id=str(protected.get("id")),
                tool_name=redact_text(tool_name, max_chars=120),
                action_ref=action_key,
                reason=reason,
                status="held",
                required_evidence=[
                    "New verified evidence for the post-change artifact, or",
                    "Explicit user release of the protection via the Console or CLI.",
                ],
                metadata={
                    "evidence_receipt_id": receipt.get("id") if receipt else None,
                    "evidence_status": receipt.get("status") if receipt else "missing",
                    "source_ref": source_ref,
                    "trust_label": trust_label,
                },
            )
            self.store.append_event(
                "challenge.detected",
                f"Protected artifact challenge: {truncate(_display_ref(ref), 150)}",
                session_id=session_id,
                task_id=task_id,
                source_ref=source_ref,
                trust_label=trust_label,
                details={
                    "challenge_id": challenge.get("id"),
                    "protected_id": protected.get("id"),
                    "artifact_ref": _display_ref(ref),
                    "tool_name": redact_text(tool_name, max_chars=120),
                    "evidence_status": receipt.get("status") if receipt else "missing",
                },
            )
            self.store.append_event(
                "action.held",
                "Action held for protected-artifact review",
                session_id=session_id,
                task_id=task_id,
                source_ref=source_ref,
                trust_label=trust_label,
                details={
                    "challenge_id": challenge.get("id"),
                    "tool_name": redact_text(tool_name, max_chars=120),
                },
            )
            challenge["evidence"] = receipt
            challenges.append(challenge)
        return challenges

    def resolve_challenges_for_action(
        self,
        action_ref: str,
        *,
        executed: bool,
        resolution: str = "",
    ) -> list[dict[str, Any]]:
        resolved: list[dict[str, Any]] = []
        for challenge in self.store.list_evidence_challenges(limit=500):
            if challenge.get("action_ref") != action_ref or challenge.get("status") != "held":
                continue
            updated = self.store.resolve_evidence_challenge(
                str(challenge["id"]),
                status="executed" if executed else "released",
                resolution=resolution,
            )
            if updated is None:
                continue
            self.store.append_event(
                "action.unlocked",
                "Protected-artifact action proceeded under host approval"
                if executed
                else "Protected-artifact action was not executed",
                details={
                    "challenge_id": updated.get("id"),
                    "artifact_ref": _display_ref(str(updated.get("artifact_ref") or "")),
                    "status": updated.get("status"),
                },
            )
            if executed and challenge.get("protected_id"):
                receipt_id = None
                protected = self.store.get_protected_artifact(str(challenge["protected_id"]))
                if protected:
                    receipt_id = protected.get("receipt_id")
                if receipt_id:
                    self.store.update_evidence_receipt(
                        str(receipt_id),
                        status="stale",
                        stale_reason="The protected artifact changed under a host-approved action.",
                    )
            resolved.append(updated)
        return resolved

    def list_protected(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return self.store.list_protected_artifacts(limit=limit)

    def list_challenges(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return self.store.list_evidence_challenges(limit=limit)

    # ------------------------------------------------------------------
    # Unverified accusations
    # ------------------------------------------------------------------
    def record_accusation(
        self,
        *,
        artifact_ref: str,
        claim: str,
        source_ref: str | None = None,
        trust_label: str = "UNTRUSTED_EXTERNAL",
        session_id: str | None = None,
        task_id: str | None = None,
        memory_ref: str | None = None,
    ) -> dict[str, Any]:
        """Store an accusation as an uncertain candidate, never as fact."""

        protected = self.store.find_active_protection(artifact_ref)
        fact = self.store.add_memory_fact(
            fact_key=f"unverified claim about {_display_ref(artifact_ref)}",
            value=claim,
            status="candidate",
            confidence=0.2,
            source_ref=source_ref,
            provenance=trust_label,
            notes=(
                "Unverified accusation recorded with uncertainty; it did not erase "
                f"evidence or protection. Protected artifact: {bool(protected)}."
            ),
            event_type="challenge.detected",
            idempotency_key=memory_ref,
        )
        return {"fact": fact, "protected": protected}


def _assess_evidence(
    method: str,
    observed_result: str,
    *,
    content_hash: str | None,
    expected_hash: str | None,
    user_confirmed: bool,
) -> tuple[bool, str, str]:
    key = method.strip().lower()
    text = str(observed_result or "")
    limitations = (
        "A receipt describes the stated verification scope only; it does not prove "
        "every claim in the artifact."
    )
    if "test" in key:
        if _NO_TESTS.search(text):
            return False, "rejected", "A test run with zero tests is not success evidence."
        if _FAILURE_TEXT.search(text):
            return False, "rejected", "The observed test output contains a failure."
        match = _TEST_COUNT.search(text)
        if not match or int(match.group("count")) <= 0:
            return False, "rejected", "The test output does not show a positive test count."
        return True, "current", "Tests passed with a positive collected test count."
    if key in {"file_sha256", "document_checksum", "content_hash"}:
        if not content_hash:
            return False, "unverified", "No content hash was computed."
        if expected_hash and not hmac.compare_digest(content_hash.lower(), expected_hash.lower()):
            return False, "rejected", "The computed content hash did not match the expected hash."
        return True, "current", "Content hash computed locally at verification time."
    if key in {"user_confirmation", "user_verified"}:
        if user_confirmed:
            return True, "current", "An explicit user confirmation was recorded."
        return False, "unverified", "A model assertion is not a user confirmation."
    if key in {"command_exit", "exit_code"}:
        return (
            False,
            "unverified",
            "A successful command exit is not, by itself, proof of a correct outcome.",
        )
    if key in {"http_status", "api_response", "database_query", "report_saved"}:
        return (
            False,
            "unverified",
            "The observation was not independently checked against an expected result.",
        )
    return False, "unverified", limitations


def _limitations(method: str) -> list[str]:
    key = method.lower()
    if "test" in key:
        return ["Only the reported test scope is covered.", "Tests can be incomplete or incorrect."]
    if key in {"file_sha256", "document_checksum", "content_hash"}:
        return ["The hash proves bytes at verification time, not factual correctness or future stability."]
    if key in {"user_confirmation", "user_verified"}:
        return ["User confirmation is a human judgement, not an automated proof."]
    return ["The receipt records an observation, not universal correctness."]


def _is_destructive(tool_name: str, args: Any) -> bool:
    name = str(tool_name or "").strip()
    if _DESTRUCTIVE_TOOLS.search(name):
        return True
    return bool(_DESTRUCTIVE_COMMAND.search(_action_text(args)))


def _action_text(args: Any) -> str:
    try:
        return json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(args)


def _safe_action_text(args: Any) -> str:
    try:
        return json.dumps(redact_mapping(args), ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return redact_text(args, max_chars=1200)


def _reference_matches(reference: str, action_text: str) -> bool:
    if not reference:
        return False
    # JSON-encoded Windows paths contain doubled backslashes.  Normalise both
    # sides before comparison so a protected absolute path still matches the
    # same path inside redacted tool arguments.
    haystack = _normalise_reference(action_text)
    variants = {
        reference,
        reference.replace("\\", "/"),
        reference.replace("/", "\\"),
        reference.replace("\\", "\\\\"),
        os.path.normcase(reference),
    }
    for variant in variants:
        normalised = _normalise_reference(variant)
        if normalised and normalised in haystack:
            return True
    # If a tool refers to the protected file by a relative or bare name, still
    # hold the action for review rather than allowing a silent mutation.
    basename = os.path.basename(reference.replace("\\", "/").rstrip("/"))
    if (
        basename
        and len(basename) >= 4
        and ("/" in reference or "\\" in reference)
        and _normalise_reference(basename) in haystack
    ):
        return True
    return False


def _normalise_reference(value: Any) -> str:
    text = str(value or "")
    text = text.replace("\\\\", "\\")
    return text.replace("\\", "/").casefold()


def _display_ref(value: str) -> str:
    text = str(value or "")
    if len(text) > 180:
        return "…" + text[-177:]
    return text


def _evidence_summary(receipt: dict[str, Any] | None) -> str:
    if not receipt:
        return "No evidence receipt is linked."
    status = str(receipt.get("status") or "unverified")
    method = str(receipt.get("verification_method") or "unknown")
    scope = str(receipt.get("scope") or "unspecified scope")
    return f"Evidence status: {status}; method: {method}; scope: {truncate(scope, 240)}."


def _sha256_file(path: Path) -> str:
    handle = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            handle.update(chunk)
    return handle.hexdigest()
