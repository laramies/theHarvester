from __future__ import annotations

import ast
import logging
import os
import subprocess
import sys
import textwrap
from pathlib import Path


def run_python(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, '-c', textwrap.dedent(script)],
        check=True,
        capture_output=True,
        text=True,
    )


def test_import_does_not_configure_application_logging() -> None:
    result = run_python(
        """
        import logging
        import sys
        import theHarvester.__main__
        sys.stdout.write(str(len(logging.getLogger().handlers)) + '\\n')
        """
    )

    assert result.stdout.splitlines()[-1] == '0'


def test_operator_output_uses_stdout_without_verbose_logging() -> None:
    result = run_python(
        """
        from theHarvester.lib.output import configure_logging, output_logger

        configure_logging(verbose=False)
        output_logger.info('operator result')
        """
    )

    assert result.stdout == 'operator result\n'
    assert result.stderr == ''


def test_diagnostics_use_stderr_only_when_verbose() -> None:
    result = run_python(
        """
        import logging
        from theHarvester.lib.output import configure_logging

        logger = logging.getLogger('theHarvester.discovery.example')
        configure_logging(verbose=False)
        logger.info('hidden diagnostic')
        configure_logging(verbose=True)
        logger.info('visible diagnostic')
        """
    )

    assert result.stdout == ''
    assert 'hidden diagnostic' not in result.stderr
    assert 'INFO theHarvester.discovery.example: visible diagnostic' in result.stderr


def test_production_code_has_no_print_calls() -> None:
    package_root = Path(__file__).parents[1] / 'theHarvester'
    print_calls = []

    for path in package_root.rglob('*.py'):
        tree = ast.parse(path.read_text())
        print_calls.extend(
            f'{path.relative_to(package_root)}:{node.lineno}'
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'print'
        )

    assert print_calls == []


def test_verbose_enables_info_diagnostics(tmp_path: Path) -> None:
    script = """import asyncio
import logging
from theHarvester.__main__ import start

try:
    asyncio.run(start())
except SystemExit:
    logging.getLogger('third_party').info('third-party info')
    raise
"""
    command = [
        sys.executable,
        '-c',
        script,
        '-d',
        'example.com',
        '-b',
        'unsupported',
    ]
    environment = {**os.environ, 'HOME': str(tmp_path)}

    normal = subprocess.run(command, capture_output=True, text=True, env=environment)
    verbose = subprocess.run([*command, '--verbose'], capture_output=True, text=True, env=environment)

    assert normal.returncode == verbose.returncode == 1
    assert 'INFO theHarvester.__main__: Verbose logging enabled' not in normal.stderr
    assert 'INFO theHarvester.__main__: Verbose logging enabled' in verbose.stderr
    assert 'third-party info' not in verbose.stderr


def test_cli_preserves_host_logging_unless_verbose_is_requested(tmp_path: Path) -> None:
    script = """import asyncio
import logging
from theHarvester.__main__ import start

root_logger = logging.getLogger()
handler = logging.StreamHandler()
root_logger.addHandler(handler)
package_logger = logging.getLogger('theHarvester')
package_logger.setLevel(logging.ERROR)

try:
    asyncio.run(start())
except SystemExit:
    print(handler in root_logger.handlers, package_logger.level)
    raise
"""
    command = [
        sys.executable,
        '-c',
        script,
        '-d',
        'example.com',
        '-b',
        'unsupported',
    ]
    environment = {**os.environ, 'HOME': str(tmp_path)}

    normal = subprocess.run(command, capture_output=True, text=True, env=environment)
    verbose = subprocess.run([*command, '--verbose'], capture_output=True, text=True, env=environment)

    assert normal.returncode == verbose.returncode == 1
    assert normal.stdout.splitlines()[-1] == f'True {logging.ERROR}'
    assert verbose.stdout.splitlines()[-1] == f'True {logging.INFO}'
