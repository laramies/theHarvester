from __future__ import annotations

import logging
import os
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def test_import_does_not_configure_application_logging() -> None:
    result = subprocess.run(
        [
            sys.executable,
            '-c',
            'import logging; import theHarvester.__main__; print(len(logging.getLogger().handlers))',
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.splitlines()[-1] == '0'


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
