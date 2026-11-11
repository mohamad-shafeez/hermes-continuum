"""Manifest, loader-contract, and Desktop surface checks."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest
import yaml

from conftest import PLUGIN_ROOT, RecordingContext

MANIFEST = yaml.safe_load((PLUGIN_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
DASHBOARD = json.loads(
    (PLUGIN_ROOT / "dashboard" / "manifest.json").read_text(encoding="utf-8")
)


def _load_plugin_module() -> types.ModuleType:
    """Load the root package exactly as Hermes' loader namespaces it."""

    name = "hermes_plugins.hermes_continuum"
    if name in sys.modules:
        return sys.modules[name]
    parent = sys.modules.get("hermes_plugins")
    if parent is None:
        parent = types.ModuleType("hermes_plugins")
        parent.__path__ = []  # type: ignore[attr-defined]
        sys.modules["hermes_plugins"] = parent
    spec = importlib.util.spec_from_file_location(
        name,
        PLUGIN_ROOT / "__init__.py",
        submodule_search_locations=[str(PLUGIN_ROOT)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_manifest_required_fields_and_dependencies() -> None:
    assert MANIFEST["name"] == "hermes-continuum"
    assert MANIFEST["version"] == "0.3.0"
    assert MANIFEST["requires_hermes"] == ">=0.22.2"
    assert MANIFEST["manifest_version"] == 2
    assert MANIFEST["license"] == "MIT"
    assert MANIFEST["python_dependencies"] == ["cryptography>=46,<51"]
    assert MANIFEST["capabilities"] == []


def test_declared_tools_match_registrations(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_plugin_module()
    ctx = RecordingContext()
    monkeypatch.setattr(
        module.ContinuumService,
        "from_plugin_storage",
        classmethod(lambda cls, **kwargs: (_ for _ in ()).throw(AssertionError("storage opened during register"))),
    )
    module.register(ctx)
    assert set(ctx.tools) == set(MANIFEST["provides_tools"])
    assert len(ctx.tools) == 12
    for name, record in ctx.tools.items():
        assert record["toolset"] == "continuum"
        assert record["schema"]["name"] == name
        assert record["schema"]["parameters"]["type"] == "object"
        assert callable(record["handler"])


def test_declared_hooks_match_registrations(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_plugin_module()
    ctx = RecordingContext()
    monkeypatch.setattr(
        module.ContinuumService,
        "from_plugin_storage",
        classmethod(lambda cls, **kwargs: (_ for _ in ()).throw(AssertionError("storage opened during register"))),
    )
    module.register(ctx)
    assert set(ctx.hooks) == set(MANIFEST["provides_hooks"])
    assert len(ctx.hooks) == 11
    assert all(callable(callback) for callback in ctx.hooks.values())


def test_cli_and_slash_registration(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_plugin_module()
    ctx = RecordingContext()
    monkeypatch.setattr(
        module.ContinuumService,
        "from_plugin_storage",
        classmethod(lambda cls, **kwargs: (_ for _ in ()).throw(AssertionError("storage opened during register"))),
    )
    module.register(ctx)
    assert "continuum" in ctx.cli_commands
    assert "continuum" in ctx.commands
    assert "forge" in ctx.commands
    assert callable(ctx.commands["continuum"]["handler"])
    assert callable(ctx.commands["forge"]["handler"])
    assert "checkpoint" in ctx.commands["continuum"]["args_hint"]


def test_register_is_storage_side_effect_free(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = _load_plugin_module()
    ctx = RecordingContext()
    called = {"value": False}

    def fail(cls, **kwargs):  # noqa: ANN001, ANN003
        called["value"] = True
        raise AssertionError("storage should be lazy")

    monkeypatch.setattr(module.ContinuumService, "from_plugin_storage", classmethod(fail))
    module.register(ctx)
    assert called["value"] is False
    assert not list(tmp_path.glob("*.db"))


def test_dashboard_manifest_is_hidden_api_only_surface() -> None:
    assert DASHBOARD["name"] == "hermes-continuum"
    assert DASHBOARD["tab"] == {"hidden": True}
    assert DASHBOARD["entry"] == "dist/index.js"
    assert DASHBOARD["api"] == "plugin_api.py"
    assert (PLUGIN_ROOT / "dashboard" / "dist" / "index.js").is_file()
    assert (PLUGIN_ROOT / "dashboard" / "plugin_api.py").is_file()


def test_desktop_plugin_uses_only_allowed_imports() -> None:
    source = (PLUGIN_ROOT / "desktop" / "plugin.js").read_text(encoding="utf-8")
    imports = re.findall(r"\bfrom\s+['\"]([^'\"]+)['\"]", source)
    imports += re.findall(r"\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", source)
    allowed = {"@hermes/plugin-sdk", "react", "react/jsx-runtime"}
    assert imports, "desktop plugin should import the SDK"
    assert set(imports) <= allowed, imports


def test_desktop_plugin_avoids_forbidden_patterns() -> None:
    source = (PLUGIN_ROOT / "desktop" / "plugin.js").read_text(encoding="utf-8")
    forbidden = [
        r"\beval\s*\(",
        r"\bnew\s+Function\b",
        r"\bdocument\.body\b",
        r"\bMutationObserver\b",
        r"\b(?:fetch|XMLHttpRequest)\s*\(",
        r"\bhttps?://",
        r"\bimport\s*\(\s*`",
    ]
    for pattern in forbidden:
        assert re.search(pattern, source) is None, pattern
    # The plugin must use jsx()/jsxs(), never JSX syntax.
    assert "jsx(" in source or "jsxs(" in source
    assert not re.search(r"<[A-Z][A-Za-z0-9]*\s", source)


def test_desktop_plugin_syntax_check() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    source = (PLUGIN_ROOT / "desktop" / "plugin.js").read_text(encoding="utf-8")
    result = subprocess.run(
        [node, "--input-type=module", "--check"],
        input=source,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


def test_dashboard_shim_syntax_check() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    result = subprocess.run(
        [node, "--check", str(PLUGIN_ROOT / "dashboard" / "dist" / "index.js")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


def test_required_docs_and_fixtures_exist() -> None:
    for name in (
        "README.md",
        "CHANGELOG.md",
        "VERIFICATION.md",
        "SUBMISSION_CHECKLIST.md",
    ):
        assert (PLUGIN_ROOT / name).is_file(), name
    assert (PLUGIN_ROOT / "fixtures" / "attack_lab_cases.json").is_file()
    assert (PLUGIN_ROOT / "docs" / "ARCHITECTURE.md").is_file()
    assert (PLUGIN_ROOT / "docs" / "SECURITY.md").is_file()
