import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path


def _dependency_names(requirements: list[str]) -> set[str]:
    return {requirement.partition('==')[0] for requirement in requirements}


def test_json_extensions_are_not_installation_requirements() -> None:
    project = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))

    assert all(not dependency.startswith('ujson') for dependency in project['project']['dependencies'])
    assert all(not dependency.startswith('types-ujson') for dependency in project['dependency-groups']['dev'])


def test_unused_packages_are_not_runtime_requirements() -> None:
    project = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))
    lock = tomllib.loads(Path('uv.lock').read_text(encoding='utf-8'))

    runtime = _dependency_names(project['project']['dependencies'])
    development = _dependency_names(project['dependency-groups']['dev'])
    locked = {package['name'] for package in lock['package']}

    assert runtime.isdisjoint({'aiofiles', 'dnspython', 'httpx', 'lxml', 'retrying'})
    assert {'aiofiles', 'dnspython', 'lxml', 'retrying'}.isdisjoint(locked)
    assert 'httpx' in development


def test_unused_packages_are_not_direct_development_requirements() -> None:
    project = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))
    lock = tomllib.loads(Path('uv.lock').read_text(encoding='utf-8'))

    development = _dependency_names(project['dependency-groups']['dev'])
    locked = {package['name'] for package in lock['package']}

    assert development.isdisjoint({'mypy', 'mypy-extensions', 'types-certifi', 'types-chardet', 'wheel'})
    assert {'mypy', 'mypy-extensions', 'types-certifi', 'types-chardet', 'wheel'}.isdisjoint(locked)
    assert 'ty' in development
    assert 'exclude-newer-package' not in project['tool']['uv']
    assert 'mypy' not in project['tool']


def test_runtime_imports_without_optional_json_extensions() -> None:
    script = textwrap.dedent(
        """
        import builtins
        import importlib

        real_import = builtins.__import__

        def import_without_ujson(name, *args, **kwargs):
            if name == 'ujson':
                raise ModuleNotFoundError('ujson is unavailable')
            return real_import(name, *args, **kwargs)

        builtins.__import__ = import_without_ujson
        for module in (
            'theHarvester.__main__',
            'theHarvester.discovery.commoncrawl',
            'theHarvester.discovery.gitlabsearch',
            'theHarvester.discovery.robtex',
            'theHarvester.discovery.subdomainfinderc99',
            'theHarvester.discovery.windvane',
            'theHarvester.lib.core',
        ):
            importlib.import_module(module)
        """
    )

    result = subprocess.run(
        [sys.executable, '-c', script],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
