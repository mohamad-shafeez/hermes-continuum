"""Host adapters: model tools, CLI, and slash commands."""

from __future__ import annotations

from .cli import (
    build_forge_slash_handler,
    build_slash_handler,
    register_cli,
    run_cli,
    setup_cli,
)
from .tools import PASSPHRASE_ENV, TOOL_SCHEMAS, build_tool_handlers

__all__ = [
    "PASSPHRASE_ENV",
    "TOOL_SCHEMAS",
    "build_forge_slash_handler",
    "build_slash_handler",
    "build_tool_handlers",
    "register_cli",
    "run_cli",
    "setup_cli",
]
