from __future__ import annotations

import logging
import os
import subprocess
import sys
import textwrap
from typing import TYPE_CHECKING

if TYPE_CHECKING:
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
        output_logger = logging.getLogger('theHarvester.output')
        state = (
            len(logging.getLogger().handlers),
            len(output_logger.handlers),
            output_logger.level,
            output_logger.propagate,
        )
        sys.stdout.write(repr(state) + '\\n')
        """
    )

    assert result.stdout.splitlines()[-1] == '(0, 0, 0, True)'


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


def test_api_example_entry_point_configures_output_and_diagnostics() -> None:
    result = run_python(
        """
        import logging
        from theHarvester.lib.api import api_example
        from theHarvester.lib.output import output_logger

        async def fake_main():
            output_logger.info('example result')
            logging.getLogger(api_example.__name__).info('example diagnostic')

        api_example.main = fake_main
        api_example.entry_point()
        """
    )

    assert result.stdout == 'example result\n'
    assert 'INFO theHarvester.lib.api.api_example: example diagnostic' in result.stderr


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


def test_verbose_logging_restores_the_package_level() -> None:
    result = run_python(
        """
        import logging
        import sys
        from theHarvester.lib.output import configure_logging

        package_logger = logging.getLogger('theHarvester')
        configure_logging(verbose=False)
        levels = [package_logger.getEffectiveLevel()]
        configure_logging(verbose=True)
        levels.append(package_logger.getEffectiveLevel())
        configure_logging(verbose=False)
        levels.append(package_logger.getEffectiveLevel())
        sys.stdout.write(repr(levels) + '\\n')
        """
    )

    assert result.stdout == f'[{logging.WARNING}, {logging.INFO}, {logging.WARNING}]\n'


def test_verbose_logging_does_not_overwrite_a_later_host_level() -> None:
    result = run_python(
        """
        import logging
        import sys
        from theHarvester.lib.output import configure_logging

        package_logger = logging.getLogger('theHarvester')
        configure_logging(verbose=True)
        package_logger.setLevel(logging.ERROR)
        configure_logging(verbose=False)
        sys.stdout.write(str(package_logger.level) + '\\n')
        """
    )

    assert result.stdout == f'{logging.ERROR}\n'


def test_rest_errors_are_visible_with_uvicorn_logging() -> None:
    result = run_python(
        """
        import logging.config
        import sys
        from unittest.mock import AsyncMock, patch

        from fastapi.testclient import TestClient
        from uvicorn.config import LOGGING_CONFIG

        logging.config.dictConfig(LOGGING_CONFIG)

        from theHarvester.lib.api import api

        client = TestClient(api.app)
        statuses = []
        with patch.object(api.__main__.Core, 'get_supportedengines', side_effect=RuntimeError('sources failure')):
            statuses.append(client.get('/sources').status_code)
        with patch.object(api.__main__, 'start', AsyncMock(side_effect=RuntimeError('dnsbrute failure'))):
            statuses.append(client.get('/dnsbrute?domain=example.com').status_code)
        with (
            patch.object(api.__main__.Core, 'get_supportedengines', return_value=['baidu']),
            patch.object(api.__main__, 'start', AsyncMock(side_effect=RuntimeError('query failure'))),
        ):
            statuses.append(client.get('/query?domain=example.com&source=baidu').status_code)
        sys.stdout.write(repr(statuses) + '\\n')
        """
    )

    assert result.stdout == '[500, 500, 500]\n'
    assert 'Error in getsources endpoint' in result.stderr
    assert 'Error in dnsbrute endpoint' in result.stderr
    assert 'Error in query endpoint' in result.stderr


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
import sys
from theHarvester.__main__ import start

root_logger = logging.getLogger()
handler = logging.StreamHandler()
root_logger.addHandler(handler)
package_logger = logging.getLogger('theHarvester')
package_logger.setLevel(logging.ERROR)

try:
    asyncio.run(start())
except SystemExit:
    sys.stdout.write(f'{handler in root_logger.handlers} {package_logger.level}\\n')
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
