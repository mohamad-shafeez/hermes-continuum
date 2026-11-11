"""Source classification and result annotation.

A label describes provenance, not truth.  External content is always labelled
as untrusted even when it looks authoritative.  The annotation is a short,
human-readable suffix; it is never used as an authorization token.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..common.redaction import contains_secret, redact_text
from ..common.time import utc_now_iso
from ..constants import (
    EXTERNAL_TOOLS,
    LOCAL_FILE_TOOLS,
    NO_LABEL_TOOLS,
    PLUGIN_ID,
    TRUST_LABELS,
)

_CREDENTIAL_PATH = re.compile(
    r"(?i)(\.env(?:\.[\w.-]+)?\b|\.ssh\b|id_rsa\b|id_ed25519\b|\.aws[\\/]|"
    r"credentials(?:\.json)?\b|auth\.json\b|\.netrc\b|\.npmrc\b|\.pypirc\b|"
    r"\.git-credentials\b|secrets?\.(?:json|ya?ml|toml)\b)"
)
_NETWORK_COMMAND = re.compile(
    r"(?i)\b(?:curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm|nc|netcat|"
    r"ncat|scp|sftp|ftp|rsync|ssh|telnet)\b"
)
_MARKER_RE = re.compile(rf"\[{re.escape(PLUGIN_ID)} source: [^\]]+\]")


def _reference(tool_name: str, args: Any) -> str:
    if not isinstance(args, dict):
        return redact_text(args, max_chars=300)
    for key in ("url", "uri", "endpoint", "href", "query", "path", "file_path", "command"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return redact_text(value, max_chars=300)
    return ""


def classify_source(tool_name: str, args: Any, result: Any = None) -> dict[str, Any]:
    """Return a conservative provenance descriptor for a tool result."""
    tool = str(tool_name or "unknown").strip().lower()
    reference = _reference(tool, args)
    if tool in EXTERNAL_TOOLS:
        sensitivity = "sensitive" if contains_secret(reference) else "unknown"
        source_type = (
            "external_web"
            if tool in {"web_fetch", "web_extract", "web_search", "web_crawl", "browser"}
            else "external_tool"
        )
        return {
            "source_type": source_type,
            "reference": reference,
            "trust_label": "UNTRUSTED_EXTERNAL",
            "provenance_confidence": "DIRECT",
            "sensitivity": sensitivity,
        }
    if tool in {"terminal", "process_manage"} and _NETWORK_COMMAND.search(reference):
        # A shell command that fetched or sent data over the network returns
        # remote content, even though the tool itself is a local terminal.
        return {
            "source_type": "external_tool",
            "reference": reference,
            "trust_label": "UNTRUSTED_EXTERNAL",
            "provenance_confidence": "DERIVED",
            "sensitivity": "sensitive" if contains_secret(reference) else "unknown",
        }
    if tool in LOCAL_FILE_TOOLS:
        sensitivity = "sensitive" if _CREDENTIAL_PATH.search(reference) else "internal"
        source_type = "local_file" if tool in {"read_file", "file_read", "view_file"} else "local_tool"
        return {
            "source_type": source_type,
            "reference": reference,
            "trust_label": "LOCAL_TOOL_OUTPUT",
            "provenance_confidence": "DIRECT",
            "sensitivity": sensitivity,
        }
    if tool.startswith("continuum_") or tool.startswith("hermes-continuum"):
        return {
            "source_type": "plugin",
            "reference": reference,
            "trust_label": "PLUGIN_GENERATED",
            "provenance_confidence": "DIRECT",
            "sensitivity": "internal",
        }
    return {
        "source_type": "unknown_tool",
        "reference": reference,
        "trust_label": "UNKNOWN",
        "provenance_confidence": "UNKNOWN",
        "sensitivity": "unknown",
    }


def _label_text(source: dict[str, Any]) -> str:
    trust = str(source.get("trust_label") or "UNKNOWN")
    if trust not in TRUST_LABELS:
        trust = "UNKNOWN"
    reference = redact_text(source.get("reference") or "", max_chars=180)
    ref_part = f" | ref={reference}" if reference else ""
    return (
        f"[{PLUGIN_ID} source: {trust} | "
        f"{source.get('provenance_confidence', 'UNKNOWN')} | "
        f"{source.get('sensitivity', 'unknown')}{ref_part} | {utc_now_iso()}]"
    )


def annotate_result(
    tool_name: str,
    args: Any,
    result: Any,
    source: dict[str, Any],
) -> str | None:
    """Attach a provenance marker without breaking structured JSON where possible.

    Returns ``None`` when the result should be left untouched.  The hook caller
    treats ``None`` as "no transformation" and lets the next plugin participate.
    """
    tool = str(tool_name or "").strip().lower()
    if tool in NO_LABEL_TOOLS or tool.startswith("continuum_"):
        return None
    if not isinstance(result, str) or not result.strip():
        return None
    marker = _label_text(source)
    if _MARKER_RE.search(result):
        # A previous pass already added a marker.  The timestamp changes on
        # every call, so match the stable marker shape instead of exact text.
        return None
    stripped = result.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(result)
        except (TypeError, ValueError):
            # It only looked like JSON.  Appending a text marker is safer than
            # trying to repair a malformed payload.
            return f"{result}\n\n{marker}"
        if isinstance(parsed, dict):
            # Additive provenance field; existing keys and types are preserved.
            if "_continuum_provenance" in parsed:
                return None
            parsed["_continuum_provenance"] = {
                "trust_label": source.get("trust_label", "UNKNOWN"),
                "provenance_confidence": source.get("provenance_confidence", "UNKNOWN"),
                "sensitivity": source.get("sensitivity", "unknown"),
                "source_type": source.get("source_type", "unknown"),
                "reference": redact_text(source.get("reference") or "", max_chars=300),
                "label": marker,
            }
            try:
                return json.dumps(parsed, ensure_ascii=False)
            except (TypeError, ValueError):
                return None
        # A JSON array cannot gain a key without changing its shape.  Record
        # provenance in the Event Spine and leave the payload untouched.
        return None
    return f"{result}\n\n{marker}"
