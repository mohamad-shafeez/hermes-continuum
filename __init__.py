"""Hermes Continuum.

One integrated plugin: an append-only Event Spine shared by Tripwire (security
decisions and source labels), Oneiros (reviewed memory and dream
consolidation), and Continuum (encrypted checkpoint handoff), plus a real
Continuum Console desktop surface.

The package deliberately keeps host imports out of the core modules.  Only this
file and :mod:`continuum_core.runtime` touch the Hermes plugin context.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from .continuum_core.adapters import (
    TOOL_SCHEMAS,
    build_forge_slash_handler,
    build_slash_handler,
    build_tool_handlers,
    register_cli,
)
from .continuum_core.common.config import ContinuumConfig
from .continuum_core.runtime import ContinuumRuntime, PluginHostRegistrar
from .continuum_core.service import ContinuumService

logger = logging.getLogger(__name__)

PLUGIN_ID = "hermes-continuum"
PLUGIN_VERSION = "0.3.0"

# Declared in plugin.yaml's provides_hooks and registered here in the same order.
HOOK_METHODS = (
    "pre_tool_call",
    "post_tool_call",
    "transform_tool_result",
    "pre_llm_call",
    "post_llm_call",
    "on_session_start",
    "on_session_end",
    "on_session_finalize",
    "on_session_reset",
    "pre_approval_request",
    "post_approval_response",
)


def _make_service_factory(ctx: Any) -> Callable[[], ContinuumService]:
    """Build a per-command service using the profile-scoped plugin storage."""

    def factory() -> ContinuumService:
        getter = getattr(ctx, "get_config", None)
        if callable(getter):
            try:
                config = ContinuumConfig.from_getter(getter)
            except Exception:
                config = ContinuumConfig()
        else:
            config = ContinuumConfig()
        return ContinuumService.from_plugin_storage(
            config=config, host_registrar=PluginHostRegistrar(ctx)
        )

    return factory


def register(ctx: Any) -> None:
    """Register hooks, tools, the CLI command, and the slash command.

    Registration is side-effect free with respect to storage: no database is
    opened until the first tool, command, or hook actually needs it.  This keeps
    the validator's capability probe and plugin enable/disable safe.
    """

    runtime = ContinuumRuntime(ctx)

    for hook_name in HOOK_METHODS:
        ctx.register_hook(hook_name, getattr(runtime, hook_name))

    handlers = build_tool_handlers(runtime)
    for schema in TOOL_SCHEMAS:
        name = str(schema["name"])
        ctx.register_tool(
            name=name,
            toolset="continuum",
            schema=schema,
            handler=handlers[name],
            description=str(schema.get("description") or ""),
            emoji="\u25c8",
        )

    service_factory = _make_service_factory(ctx)
    register_cli(ctx, service_factory)
    ctx.register_command(
        "continuum",
        build_slash_handler(service_factory),
        description=(
            "Continuum status, recall, memory review, dream consolidation, "
            "Attack Lab, checkpoints, reality checks, evidence, charters, "
            "impact previews, execution circuits, forged playbooks, and safety leases."
        ),
        args_hint=(
            "status|recall|memory|dream|attack-lab|checkpoint|reality|evidence|"
            "charter|preview|execution|playbook|forge|lease"
        ),
    )
    ctx.register_command(
        "forge",
        build_forge_slash_handler(service_factory),
        description=(
            "Preview or confirm Hephaestus forging of a reusable skill, automation "
            "blueprint, and bounded safety lease from a verified session trace."
        ),
        args_hint="list|<session_id> [--yes]",
    )
