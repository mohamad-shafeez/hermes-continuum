"""Tripwire source labelling and deterministic Attack Lab."""

from __future__ import annotations

from .attack_lab import run_attack_lab
from .policy import Decision, evaluate, is_external_tool, is_no_label_tool, is_sensitive_sink, is_sensitive_tool
from .sources import annotate_result, classify_source

__all__ = [
    "Decision",
    "annotate_result",
    "classify_source",
    "evaluate",
    "is_external_tool",
    "is_no_label_tool",
    "is_sensitive_sink",
    "is_sensitive_tool",
    "run_attack_lab",
]
