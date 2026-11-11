"""Deterministic, source-aware policy for Tripwire.

The policy never asks a model for permission.  It normalises the proposed tool
action, applies a small set of explainable rules, and returns the highest
severity result.  Rules deliberately prefer approval over silent execution for
ambiguous destructive or external actions, while blocking only high-confidence
credential exfiltration patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from ..constants import EXTERNAL_TOOLS, NO_LABEL_TOOLS, POLICY_VERSION, SENSITIVE_TOOL_HINTS

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_NETWORK_VERB = re.compile(
    r"(?i)\b(curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm|nc|netcat|ncat|"
    r"scp|sftp|ftp|rsync|ssh|telnet)\b"
)
_EXTERNAL_DEST = re.compile(
    r"(?i)(https?://|ftp://|sftp://|@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b)"
)
_CREDENTIAL_HINT = re.compile(
    r"(?i)(\.env(?:\.[\w.-]+)?\b|\.ssh\b|id_rsa\b|id_ed25519\b|\.aws[\\/]|"
    r"credentials(?:\.json)?\b|auth\.json\b|\.netrc\b|\.npmrc\b|\.pypirc\b|"
    r"\.git-credentials\b|secrets?\.(?:json|ya?ml|toml)\b|"
    r"\.config[\\/]gh[\\/]|keychain\b|private[ _-]?key\b)"
)
_SECRET_VALUE = re.compile(
    r"(?i)(sk-(?:ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|bearer\s+[A-Za-z0-9._~+/\-=]{8,}|"
    r"\$\{?(?:OPENAI|ANTHROPIC|AWS|GITHUB|GH|SLACK|HERMES)[A-Z0-9_]*\}?|"
    r"%[A-Z0-9_]*(?:KEY|TOKEN|SECRET)[A-Z0-9_]*%|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd)\s*[:=]\s*\S+)"
)
_READ_VERB = re.compile(
    r"(?i)\b(cat|type|get-content|gc|less|more|head|tail|strings|copy|cp|"
    r"read|open|print)\b"
)
_WRITE_REDIRECT = re.compile(r"(?:^|[^>])>{1,2}\s*[^\s]")
_REMOTE_SCRIPT = re.compile(
    r"(?i)(?:\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b"
    r"[^\n|]*\|\s*(?:bash|sh|zsh|pwsh|powershell|python|python3|node|iex)\b|"
    r"\b(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b|"
    r"\b(?:iex|invoke-expression)\s*\(\s*(?:iwr|irm|invoke-webrequest)\b|"
    r"\bpowershell(?:\.exe)?\s+-(?:enc|encodedcommand)\b)"
)
_DESTRUCTIVE = re.compile(
    r"(?i)(?:\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+"
    r"(?:--no-preserve-root\s+)?(?:/|~|\$HOME|\.\s*(?:$|[;&|])|\*|/etc|/usr|"
    r"/var|/home|/root|C:\\(?:Windows|Users)?)|"
    r"\brmdir\s+/s\b|\bdel\s+/[sq]\b|\bRemove-Item\b[^\n]*-Recurse\b|"
    r"\bformat\s+[A-Za-z]:|\bdiskpart\b|\bmkfs(?:\.\w+)?\b|\bdd\s+if=|\bdd\s+of=/dev/|"
    r"\bshutdown\b|\bRestart-Computer\b|\bStop-Computer\b|"
    r"\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-z]*[fdx]|\bgit\s+push\s+--force\b|"
    r"\b(?:truncate|shred)\s+-[a-z]*\s+(?:/|~|\$HOME)|\bchmod\s+-R\s+777\s+/)"
)
_PERMISSION_PERSISTENCE = re.compile(
    r"(?i)(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.config[\\/]fish|"
    r"crontab|/etc/cron|systemd|LaunchAgents|schtasks|reg\s+add|sudoers|"
    r"authorized_keys|startup|RunOnce|\\Start Menu\\Programs\\Startup)"
)
_EXTERNAL_SIDE_EFFECT = re.compile(
    r"(?i)(?:\bgit\s+push\b|\bgh\s+(?:pr|issue|release)\s+create\b|"
    r"\bnpm\s+publish\b|\bdocker\s+push\b|\bkubectl\s+(?:apply|delete|create)\b|"
    r"\bterraform\s+(?:apply|destroy)\b|\baws\s+\w+\s+(?:create|update|delete|put)\b|"
    r"\bscp\b|\bsftp\b|\brsync\b|\bssh\b|\bftp\b|"
    r"\b(?:curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm)\b[^\n]*"
    r"(?:-X\s*(?:POST|PUT|PATCH|DELETE)|--request\s*(?:POST|PUT|PATCH|DELETE)|"
    r"-d\b|--data(?:-binary|-raw)?\b|-F\b|--form\b|--upload-file\b|-T\b|"
    r"--post-data\b|-Method\s+(?:Post|Put|Patch|Delete))|"
    r"\b(?:send_email|send_message|upload_file|post_message|webhook|deploy|publish)\b)"
)
_EXTERNAL_TOOL_NAME = re.compile(
    r"(?i)^(?:send|upload|publish|deploy|webhook|post|message|email|push|"
    r"create_issue|create_pr|notify|broadcast)"
)
_SAFE_READ_COMMAND = re.compile(
    r"(?i)^\s*(?:ls|dir|pwd|cat|type|head|tail|less|more|grep|rg|find|"
    r"git\s+(?:status|diff|log|show)|echo|whoami|hostname|date|"
    r"python\s+--version|node\s+--version|pip\s+list|pip\s+show)\b"
)
_SENSITIVE_COMMAND = re.compile(
    r"(?i)\b(?:rm|del|rmdir|mv|cp|chmod|chown|mkdir|touch|tee|set-content|"
    r"add-content|out-file|invoke-webrequest|invoke-restmethod|curl|wget|scp|"
    r"sftp|ssh|git\s+push|npm\s+publish|docker\s+push|kubectl|terraform|"
    r"python|python3|node|npm|pnpm|yarn|pytest|pip\s+install|powershell|pwsh|"
    r"cmd|bash|sh|zsh)\b"
)

_PROTECTED_PATH = re.compile(
    r"(?i)(?:^|[\\/])(?:\.git[\\/]config|\.ssh[\\/]|\.aws[\\/]|\.env(?:\.[\w.-]+)?$|"
    r"auth\.json|credentials(?:\.json)?|id_rsa|id_ed25519|sudoers|"
    r"\.bashrc|\.zshrc|\.profile|\.bash_profile|systemd|LaunchAgents|"
    r"cron[\\/]|authorized_keys)"
)

# Model-facing Continuum tools can change reviewed memory or import/export a
# checkpoint.  Those are user decisions, not model decisions: even when the
# model has a plausible reason, the host must ask the user before applying one.
_PLUGIN_MUTATION_ACTIONS: dict[str, frozenset[str]] = {
    "continuum_memory_review": frozenset({"confirm", "reject", "edit", "forget"}),
    "continuum_checkpoint": frozenset({"export", "import"}),
    "continuum_evidence": frozenset({"confirm", "protect", "release"}),
    "continuum_charter": frozenset({"amend", "complete"}),
    "continuum_execution": frozenset({"reset"}),
}


# ---------------------------------------------------------------------------
# Decision model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    outcome: str
    rule_key: str
    category: str
    reason: str
    severity: int
    evidence: dict[str, Any] = field(default_factory=dict)

    def host_result(self) -> dict[str, str] | None:
        if self.outcome == "block":
            return {
                "action": "block",
                "message": self.reason,
                "rule_key": self.rule_key,
            }
        if self.outcome == "approve":
            return {
                "action": "approve",
                "message": self.reason,
                "rule_key": self.rule_key,
            }
        return None


@dataclass(frozen=True)
class _Match:
    outcome: str
    rule_key: str
    category: str
    reason: str
    severity: int
    matched: tuple[str, ...]


# ---------------------------------------------------------------------------
# Argument helpers
# ---------------------------------------------------------------------------


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "\n".join(_as_text(item) for item in value)
    if isinstance(value, dict):
        return "\n".join(_as_text(item) for item in value.values())
    return str(value)


def _args_mapping(args: Any) -> dict[str, Any]:
    return args if isinstance(args, dict) else {"value": args}


def _command(args: Any) -> str:
    mapping = _args_mapping(args)
    for key in ("command", "cmd", "script", "shell", "code", "input", "value"):
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _path(args: Any) -> str:
    mapping = _args_mapping(args)
    for key in ("path", "file_path", "filepath", "filename", "target", "destination"):
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _url(args: Any) -> str:
    mapping = _args_mapping(args)
    for key in ("url", "uri", "endpoint", "href"):
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _all_text(args: Any) -> str:
    mapping = _args_mapping(args)
    return "\n".join(
        _as_text(value)
        for key, value in mapping.items()
        if str(key).lower()
        not in {"content", "body", "text", "message", "description", "prompt"}
    )


def _arg_keys(args: Any) -> list[str]:
    return sorted(str(key) for key in _args_mapping(args).keys())[:30]


def _is_sensitive_sink(tool_name: str, args: Any) -> bool:
    tool = tool_name.lower()
    plugin_actions = _PLUGIN_MUTATION_ACTIONS.get(tool)
    if plugin_actions is not None:
        action = str(_args_mapping(args).get("action") or "").strip().lower()
        return action in plugin_actions
    if tool in {
        "write_file",
        "patch",
        "delete_file",
        "browser_exec",
        "browser_cdp",
        "send_email",
        "send_message",
        "upload_file",
        "post_message",
        "webhook",
        "deploy",
        "publish",
    }:
        return True
    if tool in {"terminal", "process_manage"}:
        command = _command(args)
        if not command.strip():
            return True
        if _WRITE_REDIRECT.search(command):
            return True
        if _SENSITIVE_COMMAND.search(command):
            return True
        # A pipeline is only automatically safe when every stage is a known
        # read-only command.  Unknown stages are treated as sensitive.
        if "|" in command:
            stages = [stage.strip() for stage in command.split("|") if stage.strip()]
            return any(not _SAFE_READ_COMMAND.search(stage) for stage in stages)
        return not bool(_SAFE_READ_COMMAND.search(command))
    return False


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _exfil_network_secret(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    if tool not in {"terminal", "process_manage", "browser_exec", "browser_cdp"}:
        return None
    command = _command(args)
    if not command:
        return None
    if not _NETWORK_VERB.search(command) or not _EXTERNAL_DEST.search(command):
        return None
    indicators: list[str] = []
    if _CREDENTIAL_HINT.search(command):
        indicators.append("credential_source")
    if _SECRET_VALUE.search(command):
        indicators.append("secret_value")
    if not indicators:
        return None
    return _Match(
        outcome="block",
        rule_key="tripwire.exfil.credential_to_network",
        category="secret_exfiltration",
        reason=(
            "Tripwire blocked a high-confidence credential-exfiltration pattern: "
            "a network command referenced a credential source or secret value. "
            "Use the host approval flow if this action was intentional."
        ),
        severity=2,
        matched=tuple(indicators) + ("network_verb", "external_destination"),
    )


def _exfil_external_tool_secret(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    if tool not in EXTERNAL_TOOLS and not _EXTERNAL_TOOL_NAME.search(tool):
        return None
    text = _all_text(args)
    url = _url(args)
    combined = f"{text}\n{url}"
    if not _SECRET_VALUE.search(combined):
        return None
    return _Match(
        outcome="block",
        rule_key="tripwire.exfil.secret_to_external_tool",
        category="secret_exfiltration",
        reason=(
            "Tripwire blocked a request that appears to send a credential value "
            "to an external tool or destination. Use the host approval flow if "
            "this action was intentional."
        ),
        severity=2,
        matched=("secret_value", "external_tool"),
    )


def _remote_script(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    if tool not in {"terminal", "process_manage", "browser_exec", "browser_cdp"}:
        return None
    command = _command(args)
    if not command or not _REMOTE_SCRIPT.search(command):
        return None
    return _Match(
        outcome="approve",
        rule_key="tripwire.execution.remote_script",
        category="code_execution",
        reason=(
            "Tripwire requires approval before executing a script downloaded "
            "from a remote source or a shell command hidden in an encoded payload."
        ),
        severity=1,
        matched=("remote_script",),
    )


def _destructive(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    if tool not in {"terminal", "process_manage"}:
        return None
    command = _command(args)
    if not command or not _DESTRUCTIVE.search(command):
        return None
    return _Match(
        outcome="approve",
        rule_key="tripwire.destructive.broad_operation",
        category="destructive_file_operation",
        reason=(
            "Tripwire requires approval for a broad destructive operation that "
            "could affect important files or system state."
        ),
        severity=1,
        matched=("destructive_command",),
    )


def _permission_persistence(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    if tool in {"terminal", "process_manage"}:
        command = _command(args)
        if not command:
            return None
        if _PERMISSION_PERSISTENCE.search(command) and (
            _WRITE_REDIRECT.search(command)
            or re.search(r"(?i)\b(?:crontab|schtasks|reg\s+add|tee|set-content|add-content|out-file)\b", command)
        ):
            return _Match(
                outcome="approve",
                rule_key="tripwire.persistence.startup_or_shell_profile",
                category="permission_persistence",
                reason=(
                    "Tripwire requires approval before changing startup, shell "
                    "profile, scheduled-task, or permission-persistence state."
                ),
                severity=1,
                matched=("persistence_path", "write_operation"),
            )
    if tool in {"write_file", "patch", "file_write", "file_edit"}:
        path = _path(args)
        if path and _PERMISSION_PERSISTENCE.search(path):
            return _Match(
                outcome="approve",
                rule_key="tripwire.persistence.startup_or_shell_profile",
                category="permission_persistence",
                reason=(
                    "Tripwire requires approval before writing to a startup, "
                    "shell profile, scheduled-task, or permission-persistence path."
                ),
                severity=1,
                matched=("persistence_path", "write_operation"),
            )
    return None


def _credential_read(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    if tool in {"read_file", "file_read", "view_file"}:
        path = _path(args)
        if path and _CREDENTIAL_HINT.search(path):
            return _Match(
                outcome="approve",
                rule_key="tripwire.secret.credential_file_read",
                category="secret_access",
                reason=(
                    "Tripwire requires approval before reading a credential, "
                    "private-key, or secret-bearing file."
                ),
                severity=1,
                matched=("credential_path", "read_operation"),
            )
    if tool in {"terminal", "process_manage"}:
        command = _command(args)
        if command and _READ_VERB.search(command) and _CREDENTIAL_HINT.search(command):
            if not _NETWORK_VERB.search(command):
                return _Match(
                    outcome="approve",
                    rule_key="tripwire.secret.credential_file_read",
                    category="secret_access",
                    reason=(
                        "Tripwire requires approval before reading a credential, "
                        "private-key, or secret-bearing file."
                    ),
                    severity=1,
                    matched=("credential_path", "read_operation"),
                )
    return None


def _sensitive_path_write(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    if tool not in {"write_file", "patch", "file_write", "file_edit", "delete_file"}:
        return None
    path = _path(args)
    if path and _PROTECTED_PATH.search(path):
        return _Match(
            outcome="approve",
            rule_key="tripwire.destructive.protected_path",
            category="destructive_file_operation",
            reason=(
                "Tripwire requires approval before modifying a protected path "
                "such as a credential store, repository metadata, or system file."
            ),
            severity=1,
            matched=("protected_path", "write_operation"),
        )
    return None


def _external_side_effect(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    if _EXTERNAL_TOOL_NAME.search(tool):
        return _Match(
            outcome="approve",
            rule_key="tripwire.external.side_effect",
            category="external_communication",
            reason=(
                "Tripwire requires approval before sending, uploading, publishing, "
                "or otherwise causing an external side effect."
            ),
            severity=1,
            matched=("external_tool_name",),
        )
    if tool in {"terminal", "process_manage"}:
        command = _command(args)
        if command and _EXTERNAL_SIDE_EFFECT.search(command):
            return _Match(
                outcome="approve",
                rule_key="tripwire.external.side_effect",
                category="external_communication",
                reason=(
                    "Tripwire requires approval before a network command sends, "
                    "uploads, deletes, or changes remote state."
                ),
                severity=1,
                matched=("external_side_effect",),
            )
    return None


def _plugin_state_change(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    actions = _PLUGIN_MUTATION_ACTIONS.get(tool)
    if actions is None:
        return None
    action = str(_args_mapping(args).get("action") or "").strip().lower()
    if action not in actions:
        return None
    return _Match(
        outcome="approve",
        rule_key="tripwire.plugin.state_change",
        category="plugin_state_change",
        reason=(
            "Tripwire requires explicit user approval before a model-facing tool "
            "changes reviewed memory or imports/exports a Continuum checkpoint."
        ),
        severity=1,
        matched=("plugin_mutation", action),
    )


def _context_untrusted(tool: str, args: Any, context: dict[str, Any]) -> _Match | None:
    if context.get("context_trust") != "UNTRUSTED_EXTERNAL":
        return None
    if not _is_sensitive_sink(tool, args):
        return None
    return _Match(
        outcome="approve",
        rule_key="tripwire.context.untrusted_sensitive_sink",
        category="source_trust",
        reason=(
            "Tripwire requires approval because this sensitive action follows "
            "untrusted external content in the same session. Review the action "
            "against the user's original request."
        ),
        severity=1,
        matched=("untrusted_external_context", "sensitive_sink"),
    )


_RULES: tuple[Callable[[str, Any, dict[str, Any]], _Match | None], ...] = (
    _exfil_network_secret,
    _exfil_external_tool_secret,
    _remote_script,
    _destructive,
    _permission_persistence,
    _credential_read,
    _sensitive_path_write,
    _external_side_effect,
    _plugin_state_change,
    _context_untrusted,
)


def evaluate(
    tool_name: str,
    args: Any,
    *,
    context_trust: str | None = None,
    source_ref: str | None = None,
) -> Decision:
    """Evaluate one proposed action deterministically.

    The returned decision is safe to show to the model.  Evidence contains only
    rule names and argument-key names, never raw commands or secret values.
    """
    tool = str(tool_name or "unknown").strip().lower()
    context = {"context_trust": context_trust or "UNKNOWN", "source_ref": source_ref}
    matches: list[_Match] = []
    for rule in _RULES:
        try:
            match = rule(tool, args, context)
        except Exception:
            # A broken rule must never become an allow.  The adapter turns this
            # sentinel into an explicit block; no model input is involved.
            return Decision(
                outcome="block",
                rule_key="tripwire.internal.policy_error",
                category="internal_error",
                reason=(
                    "Tripwire could not evaluate the action safely and blocked it "
                    "fail-closed. Check the plugin logs and try again."
                ),
                severity=2,
                evidence={
                    "error": "policy_rule_exception",
                    "tool_name": tool,
                    "arg_keys": _arg_keys(args),
                },
            )
        if match is not None:
            matches.append(match)
    if not matches:
        return Decision(
            outcome="allow",
            rule_key="tripwire.default.allow",
            category="no_sensitive_match",
            reason="No sensitive Tripwire pattern matched.",
            severity=0,
            evidence={
                "tool_name": tool,
                "arg_keys": _arg_keys(args),
                "source_ref": source_ref,
                "context_trust": context_trust or "UNKNOWN",
                "policy_version": POLICY_VERSION,
            },
        )
    # Block > approve > allow.  Rule order breaks ties deterministically.
    best = max(enumerate(matches), key=lambda item: (item[1].severity, -item[0]))[1]
    return Decision(
        outcome=best.outcome,
        rule_key=best.rule_key,
        category=best.category,
        reason=best.reason,
        severity=best.severity,
        evidence={
            "tool_name": tool,
            "arg_keys": _arg_keys(args),
            "matched": list(best.matched),
            "all_rule_keys": [match.rule_key for match in matches],
            "source_ref": source_ref,
            "context_trust": context_trust or "UNKNOWN",
            "policy_version": POLICY_VERSION,
        },
    )


def is_external_tool(tool_name: str) -> bool:
    return str(tool_name or "").strip().lower() in EXTERNAL_TOOLS


def is_no_label_tool(tool_name: str) -> bool:
    return str(tool_name or "").strip().lower() in NO_LABEL_TOOLS


def is_sensitive_tool(tool_name: str) -> bool:
    tool = str(tool_name or "").strip().lower()
    return tool in SENSITIVE_TOOL_HINTS or bool(_EXTERNAL_TOOL_NAME.search(tool))


def is_sensitive_sink(tool_name: str, args: Any) -> bool:
    return _is_sensitive_sink(tool_name, args)
