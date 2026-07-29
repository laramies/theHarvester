from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


WORKFLOW_DIR = Path(__file__).parents[1] / '.github' / 'workflows'
CI_WORKFLOW_PATH = WORKFLOW_DIR / 'theHarvester.yml'
SMOKE_WORKFLOW_PATH = WORKFLOW_DIR / 'provider-smoke.yml'


def _workflow(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)


def test_routine_ci_is_read_only_and_offline() -> None:
    workflow = _workflow(CI_WORKFLOW_PATH)
    assert workflow['permissions'] == {'contents': 'read'}
    assert set(workflow['on']) == {'push', 'pull_request', 'workflow_dispatch'}

    routine_job = workflow['jobs']['Python']
    commands = '\n'.join(step.get('run', '') for step in routine_job['steps'])
    assert 'git push' not in commands
    assert 'theHarvester -d' not in commands
    assert '\npytest\n' in f'\n{commands.strip()}\n'


def test_live_provider_smoke_requires_manual_dispatch() -> None:
    workflow = _workflow(SMOKE_WORKFLOW_PATH)
    smoke_job = workflow['jobs']['Passive-provider-smoke']
    commands = '\n'.join(step.get('run', '') for step in smoke_job['steps'])

    assert set(workflow['on']) == {'workflow_dispatch'}
    assert workflow['permissions'] == {'contents': 'read'}
    assert smoke_job['env']['SMOKE_TEST_DOMAIN'] == 'example.com'
    assert 'pytest --run-live-network -m live_network' in commands
