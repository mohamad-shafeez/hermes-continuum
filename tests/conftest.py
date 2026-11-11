"""Shared fixtures for the Hermes Continuum test suite.

The suite is deliberately offline: it uses temporary plugin databases and a
recording host context.  No Hermes session database, provider, browser, or
external service is touched.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
TESTS_ROOT = Path(__file__).resolve().parent
for path in (str(PLUGIN_ROOT), str(TESTS_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from continuum_core.common.config import ContinuumConfig
from continuum_core.service import ContinuumService


class RecordingContext:
    """Minimal stand-in for the verified Hermes plugin context."""

    def __init__(self, settings: dict[str, Any] | None = None):
        self.settings = dict(settings or {})
        self.hooks: dict[str, Any] = {}
        self.tools: dict[str, dict[str, Any]] = {}
        self.cli_commands: dict[str, dict[str, Any]] = {}
        self.commands: dict[str, dict[str, Any]] = {}
        self.skills: dict[str, dict[str, Any]] = {}
        self.blueprints: dict[str, dict[str, Any]] = {}
        self.cron_execution: Any = None

    def current_cron_execution(self) -> Any:
        return self.cron_execution

    def register_skill(
        self,
        name: str,
        path: Path,
        description: str = "",
        frontmatter: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.skills[name] = {
            "name": name,
            "path": Path(path),
            "description": description,
            "frontmatter": dict(frontmatter or {}),
        }
        return {"kind": "skill", "key": name}

    def register_automation_blueprint(self, key: str, **fields: Any) -> dict[str, Any]:
        self.blueprints[key] = {"key": key, **fields}
        return {"kind": "blueprint", "key": key}

    def get_config(self, key: str, default: Any = None) -> Any:
        return self.settings.get(key, default)

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks[name] = callback

    def register_tool(
        self,
        name: str,
        toolset: str,
        schema: dict[str, Any],
        handler: Any,
        **kwargs: Any,
    ) -> None:
        self.tools[name] = {
            "name": name,
            "toolset": toolset,
            "schema": schema,
            "handler": handler,
            **kwargs,
        }

    def register_cli_command(
        self,
        name: str,
        help: str,
        setup_fn: Any,
        handler_fn: Any = None,
        description: str = "",
    ) -> None:
        self.cli_commands[name] = {
            "name": name,
            "help": help,
            "setup_fn": setup_fn,
            "handler_fn": handler_fn,
            "description": description,
        }

    def register_command(
        self,
        name: str,
        handler: Any,
        description: str = "",
        args_hint: str = "",
        argument_mode: Any = None,
    ) -> None:
        self.commands[name] = {
            "name": name,
            "handler": handler,
            "description": description,
            "args_hint": args_hint,
            "argument_mode": argument_mode,
        }


@pytest.fixture
def config() -> ContinuumConfig:
    return ContinuumConfig()


@pytest.fixture
def service(tmp_path: Path, config: ContinuumConfig):
    instance = ContinuumService.from_path(
        tmp_path / "spine.db",
        config=config,
        checkpoint_dir=tmp_path / "checkpoints",
    )
    try:
        yield instance
    finally:
        instance.close()


@pytest.fixture
def recording_ctx() -> RecordingContext:
    return RecordingContext()


@pytest.fixture
def runtime(service: ContinuumService, recording_ctx: RecordingContext):
    from continuum_core.runtime import ContinuumRuntime

    instance = ContinuumRuntime(recording_ctx)
    # The runtime normally opens profile-scoped plugin storage lazily.  Tests
    # inject the temporary service directly so no Hermes profile is required.
    instance._service = service
    return instance
