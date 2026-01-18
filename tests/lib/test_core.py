from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
import yaml

import theHarvester.lib.core as core_module
from theHarvester.lib.core import CONFIG_DIRS, DATA_DIR, Core


@pytest.fixture(autouse=True)
def mock_environ(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))


def mock_read_text(mocked: dict[Path, str | Exception]):
    read_text = Path.read_text

    def _read_text(self: Path, *args, **kwargs):
        if result := mocked.get(self):
            if isinstance(result, Exception):
                raise result
            return result
        return read_text(self, *args, **kwargs)

    return _read_text


@pytest.mark.parametrize(
    ("name", "contents", "expected"),
    [
        ("api-keys", "apikeys: {}", {}),
        ("proxies", "http: [localhost:8080]", {"http": ["http://localhost:8080"], "socks5": []}),
    ],
)
@pytest.mark.parametrize("dir", CONFIG_DIRS)
def test_read_config_searches_config_dirs(
    name: str, contents: str, expected: Any, dir: Path, capsys
):
    file = dir.expanduser() / f"{name}.yaml"
    config_files = [d.expanduser() / file.name for d in CONFIG_DIRS]
    side_effect = mock_read_text(
        {f: contents if f == file else FileNotFoundError() for f in config_files}
    )

    with mock.patch("pathlib.Path.read_text", autospec=True, side_effect=side_effect):
        got = Core.api_keys() if name == "api-keys" else Core.proxy_list()

    assert got == expected
    assert f"Read {file.name} from {file}" in capsys.readouterr().out


@pytest.mark.parametrize("name", ("api-keys", "proxies"))
def test_read_config_copies_default_to_home(name: str, capsys):
    file = Path(f"~/.theHarvester/{name}.yaml").expanduser()
    config_files = [d.expanduser() / file.name for d in CONFIG_DIRS]
    side_effect = mock_read_text({f: FileNotFoundError() for f in config_files})

    with mock.patch("pathlib.Path.read_text", autospec=True, side_effect=side_effect):
        got = Core.api_keys() if name == "api-keys" else Core.proxy_list()

    default = yaml.safe_load((DATA_DIR / file.name).read_text())
    expected = (
        default["apikeys"]
        if name == "api-keys"
        else {
            "http": [f"http://{h}" for h in default["http"]] if default.get("http") else [],
            "socks5": [f"socks5://{h}" for h in default["socks5"]] if default.get("socks5") else [],
        }
    )
    assert got == expected
    assert f"Created default {file.name} at {file}" in capsys.readouterr().out
    assert file.exists()


def _extract_required_apikey_entries_from_core() -> dict[str, set[str]]:
    tree = ast.parse(Path(core_module.__file__).read_text(encoding="utf-8"))
    core_class = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Core"), None)
    assert core_class is not None, "Unable to locate `class Core` in theHarvester.lib.core"

    required: dict[str, set[str]] = {}
    for node in ast.walk(core_class):
        if not isinstance(node, ast.Subscript):
            continue

        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Subscript):
            sl = current.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                parts.append(sl.value)
                current = current.value
                continue
            break

        if not parts or not isinstance(current, ast.Call):
            continue

        func = current.func
        is_core_api_keys = (
            isinstance(func, ast.Attribute)
            and func.attr == "api_keys"
            and isinstance(func.value, ast.Name)
            and func.value.id == "Core"
        )
        if not is_core_api_keys:
            continue

        parts.reverse()
        provider = parts[0]
        required.setdefault(provider, set())
        if len(parts) > 1:
            required[provider].add(parts[1])

    return required


def test_api_keys_yaml_is_in_sync_with_core_accessors():
    required = _extract_required_apikey_entries_from_core()
    assert required, "No API-key references were detected in `Core`"

    config = yaml.safe_load((DATA_DIR / "api-keys.yaml").read_text(encoding="utf-8"))
    apikeys = config["apikeys"]

    missing_providers = sorted(set(required) - set(apikeys))
    assert not missing_providers, f"Missing providers in api-keys.yaml: {missing_providers}"

    missing_fields: dict[str, list[str]] = {}
    for provider, fields in required.items():
        for field in sorted(fields):
            if field not in apikeys[provider]:
                missing_fields.setdefault(provider, []).append(field)

    assert not missing_fields, f"Missing fields in api-keys.yaml: {missing_fields}"
