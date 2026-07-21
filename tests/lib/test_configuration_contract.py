from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import pytest
import yaml

from theHarvester.lib.configuration import FileSystemCredentialAdapter

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

    from theHarvester.lib.core import Core


class ConfigurationEnvironment(NamedTuple):
    core: type[Core]
    module: ModuleType
    directories: list[Path]


def test_importing_core_does_not_access_configuration_files(tmp_path: Path) -> None:
    script = textwrap.dedent(
        """
        import sys

        configuration_accesses: list[str] = []

        def record_configuration_access(event: str, arguments: tuple[object, ...]) -> None:
            if event != 'open':
                return
            path = arguments[0]
            if isinstance(path, str) and path.endswith(('api-keys.yaml', 'proxies.yaml')):
                configuration_accesses.append(path)

        sys.addaudithook(record_configuration_access)

        import theHarvester.lib.core

        assert configuration_accesses == [], configuration_accesses

        first_proxy_list = theHarvester.lib.core.AsyncFetcher().proxy_list
        access_count = len(configuration_accesses)
        second_proxy_list = theHarvester.lib.core.AsyncFetcher().proxy_list

        assert second_proxy_list is first_proxy_list
        assert len(configuration_accesses) == access_count
        """
    )
    environment = os.environ.copy()
    environment['HOME'] = str(tmp_path)

    result = subprocess.run(
        [sys.executable, '-c', script],
        capture_output=True,
        check=False,
        cwd=Path(__file__).parents[2],
        env=environment,
        text=True,
    )

    assert result.returncode == 0, result.stderr


@pytest.fixture
def configuration_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> ConfigurationEnvironment:
    monkeypatch.setenv('HOME', str(tmp_path))
    import theHarvester.lib.core as core_module

    directories = [tmp_path / name for name in ('user', 'system', 'local')]
    for directory in directories:
        directory.mkdir()
    monkeypatch.setattr(core_module, 'CONFIG_DIRS', directories)
    return ConfigurationEnvironment(core_module.Core, core_module, directories)


@pytest.mark.parametrize(
    ('present_indexes', 'expected_key'),
    [
        ((0, 1, 2), 'user-key'),
        ((1, 2), 'system-key'),
        ((2,), 'local-key'),
    ],
)
def test_api_keys_and_filesystem_credentials_use_first_available_configuration(
    configuration_environment: ConfigurationEnvironment,
    present_indexes: tuple[int, ...],
    expected_key: str,
) -> None:
    core = configuration_environment.core
    configuration_dirs = configuration_environment.directories
    keys = ('user-key', 'system-key', 'local-key')
    for index in present_indexes:
        (configuration_dirs[index] / 'api-keys.yaml').write_text(
            f'apikeys:\n  brave:\n    key: {keys[index]}\n',
            encoding='utf-8',
        )

    assert (core.api_keys(), FileSystemCredentialAdapter().get('brave')) == (
        {'brave': {'key': expected_key}},
        expected_key,
    )


def test_missing_api_keys_uses_and_creates_bundled_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    configuration_environment: ConfigurationEnvironment,
) -> None:
    core = configuration_environment.core
    core_module = configuration_environment.module
    configuration_dirs = configuration_environment.directories
    bundled_directory = tmp_path / 'bundled'
    bundled_directory.mkdir()
    bundled_content = 'apikeys:\n  brave:\n    key: bundled-key\n'
    (bundled_directory / 'api-keys.yaml').write_text(bundled_content, encoding='utf-8')
    monkeypatch.setattr(core_module, 'DATA_DIR', bundled_directory)

    assert (
        core.api_keys(),
        (configuration_dirs[0] / 'api-keys.yaml').read_text(encoding='utf-8'),
    ) == (
        {'brave': {'key': 'bundled-key'}},
        bundled_content,
    )


@pytest.mark.parametrize(
    ('filename', 'configuration_reader'),
    [
        ('api-keys.yaml', 'api_keys'),
        ('proxies.yaml', 'proxy_list'),
    ],
)
def test_malformed_configuration_raises_yaml_error(
    configuration_environment: ConfigurationEnvironment,
    filename: str,
    configuration_reader: str,
) -> None:
    core = configuration_environment.core
    configuration_dirs = configuration_environment.directories
    (configuration_dirs[0] / filename).write_text('key: [unterminated\n', encoding='utf-8')
    reader: Callable[[], dict[str, object]] = getattr(core, configuration_reader)

    with pytest.raises(yaml.YAMLError):
        reader()


def test_provider_accessors_return_single_and_multi_field_credentials(
    configuration_environment: ConfigurationEnvironment,
) -> None:
    core = configuration_environment.core
    configuration_dirs = configuration_environment.directories
    (configuration_dirs[0] / 'api-keys.yaml').write_text(
        'apikeys:\n  bevigil:\n    key: bevigil-key\n  censys:\n    id: censys-id\n    secret: censys-secret\n',
        encoding='utf-8',
    )

    assert (core.bevigil_key(), core.censys_key()) == (
        'bevigil-key',
        ('censys-id', 'censys-secret'),
    )


@pytest.mark.parametrize(
    ('contents', 'expected'),
    [
        (
            'http: [proxy.local:8080]\nsocks5: [socks.local:1080]\n',
            {
                'http': ['http://proxy.local:8080'],
                'socks5': ['socks5://socks.local:1080'],
            },
        ),
        ('http:\n', {'http': [], 'socks5': []}),
    ],
)
def test_proxy_lookup_normalizes_configured_addresses(
    configuration_environment: ConfigurationEnvironment,
    contents: str,
    expected: dict[str, list[str]],
) -> None:
    core = configuration_environment.core
    configuration_dirs = configuration_environment.directories
    (configuration_dirs[0] / 'proxies.yaml').write_text(contents, encoding='utf-8')

    assert core.proxy_list() == expected
