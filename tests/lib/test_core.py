from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest
import yaml

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
        ("proxies", "http: [localhost:8080]", ["http://localhost:8080"]),
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
        else [f"http://{h}" for h in default["http"]]
    )
    assert got == expected
    assert f"Created default {file.name} at {file}" in capsys.readouterr().out
    assert file.exists()
