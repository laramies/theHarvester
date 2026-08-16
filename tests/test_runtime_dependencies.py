import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path


def test_json_extensions_are_not_installation_requirements() -> None:
    project = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))

    assert all(not dependency.startswith('ujson') for dependency in project['project']['dependencies'])
    assert all(not dependency.startswith('types-ujson') for dependency in project['dependency-groups']['dev'])


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
