"""Installation layout, loader compatibility, and Hermes validator/doctor smoke."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest
import yaml

from conftest import RecordingContext

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
# The host smoke test is opt-in so a checkout does not assume one machine's
# install location. Set HERMES_LAUNCHER to the real launcher to run it.
HERMES_LAUNCHER = Path(os.environ.get("HERMES_LAUNCHER", ""))
REQUIRED_FILES = [
    "plugin.yaml",
    "__init__.py",
    "continuum_core/__init__.py",
    "dashboard/manifest.json",
    "dashboard/plugin_api.py",
    "dashboard/dist/index.js",
    "desktop/plugin.js",
    "fixtures/attack_lab_cases.json",
    "README.md",
    "CHANGELOG.md",
    "docs/ARCHITECTURE.md",
    "docs/SECURITY.md",
]


def _load_plugin(root: Path):
    package_name = "hermes_plugins"
    if package_name not in sys.modules:
        package = types.ModuleType(package_name)
        package.__path__ = []  # type: ignore[attr-defined]
        sys.modules[package_name] = package
    module_name = "hermes_plugins.hermes_continuum"
    for key in list(sys.modules):
        if key == module_name or key.startswith(module_name + "."):
            del sys.modules[key]
    spec = importlib.util.spec_from_file_location(
        module_name,
        root / "__init__.py",
        submodule_search_locations=[str(root)],
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_required_installation_files_exist() -> None:
    for relative in REQUIRED_FILES:
        assert (PLUGIN_ROOT / relative).is_file(), relative


def test_manifest_declares_the_verified_surface() -> None:
    manifest = yaml.safe_load((PLUGIN_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    assert manifest["name"] == "hermes-continuum"
    assert manifest["version"] == "0.3.0"
    assert manifest["requires_hermes"] == ">=0.22.2"
    assert len(manifest["provides_hooks"]) == 11
    assert len(manifest["provides_tools"]) == 12
    assert manifest["python_dependencies"] == ["cryptography>=46,<51"]
    assert manifest["manifest_version"] == 2
    assert "recall_limit" in manifest["config_schema"]
    assert "checkpoint_dir" in manifest["config_schema"]
    assert "enable_hephaestus" in manifest["config_schema"]
    assert "hephaestus_cron_enforce" in manifest["config_schema"]


def test_dashboard_manifest_is_hidden_and_api_only() -> None:
    manifest = json.loads(
        (PLUGIN_ROOT / "dashboard" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["name"] == "hermes-continuum"
    assert manifest["tab"]["hidden"] is True
    assert manifest["api"] == "plugin_api.py"
    assert manifest["entry"] == "dist/index.js"


def test_root_loader_registers_declared_surface_without_opening_storage(monkeypatch) -> None:
    module = _load_plugin(PLUGIN_ROOT)
    ctx = RecordingContext()

    def forbidden(*args, **kwargs):
        raise AssertionError("registration opened plugin storage")

    monkeypatch.setattr(
        module.ContinuumService, "from_plugin_storage", classmethod(forbidden)
    )
    module.register(ctx)
    assert set(ctx.hooks) == set(module.HOOK_METHODS)
    assert set(ctx.tools) == set(module.TOOL_SCHEMAS[i]["name"] for i in range(12))
    assert set(ctx.cli_commands) == {"continuum"}
    assert set(ctx.commands) == {"continuum", "forge"}
    assert all(record["toolset"] == "continuum" for record in ctx.tools.values())
    assert ctx.tools["continuum_status"]["schema"]["parameters"]["type"] == "object"


def test_plugin_loads_from_a_copied_profile_layout(tmp_path: Path) -> None:
    target = tmp_path / "plugins" / "hermes-continuum"
    target.mkdir(parents=True)
    for name in ("plugin.yaml", "__init__.py", "README.md", "CHANGELOG.md"):
        shutil.copy2(PLUGIN_ROOT / name, target / name)
    for name in ("continuum_core", "dashboard", "desktop", "fixtures", "docs"):
        shutil.copytree(
            PLUGIN_ROOT / name,
            target / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
        )
    module = _load_plugin(target)
    ctx = RecordingContext()
    module.register(ctx)
    assert len(ctx.hooks) == 11
    assert len(ctx.tools) == 12
    assert (target / "desktop" / "plugin.js").is_file()


def test_attack_lab_fixture_is_inert_and_complete() -> None:
    cases = json.loads(
        (PLUGIN_ROOT / "fixtures" / "attack_lab_cases.json").read_text(encoding="utf-8")
    )
    assert len(cases) == 12
    assert {case["expected"] for case in cases} == {"allow", "approve", "block"}
    assert all("id" in case and "args" in case for case in cases)


def test_desktop_plugin_uses_only_sdk_surfaces() -> None:
    source = (PLUGIN_ROOT / "desktop" / "plugin.js").read_text(encoding="utf-8")
    assert "from '@hermes/plugin-sdk'" in source or 'from "@hermes/plugin-sdk"' in source
    assert "from 'react'" in source or 'from "react"' in source
    assert "jsx(" in source or "jsxs(" in source
    assert "eval(" not in source
    assert "new Function" not in source
    assert "document.body" not in source
    assert "[data-slot]" not in source
    assert "window.fetch" not in source
    assert "ctx.rest(" in source
    assert "ctx.rest('/retention'" in source
    assert "ctx.rest('/checkpoints/export'" in source
    assert "ctx.rest('/attack-lab/run'" in source


def test_desktop_plugin_syntax() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    source = (PLUGIN_ROOT / "desktop" / "plugin.js").read_text(encoding="utf-8")
    result = subprocess.run(
        [node, "--input-type=module", "--check"],
        input=source,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(
    sys.platform != "win32" or not HERMES_LAUNCHER.is_file(),
    reason="set HERMES_LAUNCHER to a Windows Hermes launcher to run this host test",
)
def test_hermes_validator_and_doctor() -> None:
    # The installed Hermes plugin discovery can be slow on Windows when many
    # bundled providers are present.  This test verifies the validator result,
    # not cold-start latency; keep a generous ceiling so a valid plugin is not
    # reported as a failure solely because discovery exceeded four minutes.
    validate = subprocess.run(
        ["cmd", "/c", str(HERMES_LAUNCHER), "plugins", "validate", str(PLUGIN_ROOT), "--json"],
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert validate.returncode == 0, validate.stdout + validate.stderr
    assert '"ok": true' in validate.stdout.lower() or '"ok":true' in validate.stdout.lower()

    doctor = subprocess.run(
        ["cmd", "/c", str(HERMES_LAUNCHER), "plugins", "doctor", str(PLUGIN_ROOT), "--ci"],
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert doctor.returncode == 0, doctor.stdout + doctor.stderr
    combined = (doctor.stdout + doctor.stderr).lower()
    assert "12 tool(s)" in combined
    assert "11 hook(s)" in combined
