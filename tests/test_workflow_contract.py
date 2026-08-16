from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

WORKFLOW_DIR = Path(__file__).parents[1] / '.github' / 'workflows'
CI_WORKFLOW_PATH = WORKFLOW_DIR / 'theHarvester.yml'
SMOKE_WORKFLOW_PATH = WORKFLOW_DIR / 'provider-smoke.yml'
HARVESTVIEW_WORKFLOW_PATH = WORKFLOW_DIR / 'harvestview-e2e.yml'
CONTAINER_WORKFLOW_PATH = WORKFLOW_DIR / 'harvestview-container.yml'


def _workflow(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)


def test_routine_ci_is_read_only_and_offline() -> None:
    workflow = _workflow(CI_WORKFLOW_PATH)
    assert workflow['permissions'] == {'contents': 'read'}
    assert set(workflow['on']) == {'workflow_call', 'push', 'pull_request'}

    routine_job = workflow['jobs']['Python']
    commands = '\n'.join(step.get('run', '') for step in routine_job['steps'])
    assert 'git push' not in commands
    assert 'theHarvester -d' not in commands
    assert '\npytest\n' in f'\n{commands.strip()}\n'
    assert 'mypy theHarvester' in commands
    assert routine_job['strategy']['matrix']['python-version'] == ['3.12', '3.13', '3.14']


def test_release_validation_is_manual_and_composes_existing_checks() -> None:
    workflow = _workflow(SMOKE_WORKFLOW_PATH)

    assert workflow['name'] == 'Release validation'
    assert set(workflow['on']) == {'workflow_dispatch'}
    assert workflow['permissions'] == {'contents': 'read'}
    live_input = workflow['on']['workflow_dispatch']['inputs']['run_live']
    assert live_input['type'] == 'boolean'
    assert live_input['default'] == 'false'

    reused_workflows = {job['uses'] for job in workflow['jobs'].values() if 'uses' in job}
    assert reused_workflows == {
        './.github/workflows/harvestview-container.yml',
        './.github/workflows/harvestview-e2e.yml',
        './.github/workflows/theHarvester.yml',
    }
    assert 'package-smoke' in workflow['jobs']


def test_release_live_checks_are_opt_in_p0_and_fixed_to_mozilla() -> None:
    workflow = _workflow(SMOKE_WORKFLOW_PATH)
    live_jobs = [job for name, job in workflow['jobs'].items() if name.startswith('live-')]

    assert live_jobs
    assert all(job['if'] == '${{ inputs.run_live }}' for job in live_jobs)
    assert all(job['env']['SMOKE_TEST_DOMAIN'] == 'mozilla.org' for job in live_jobs)
    assert workflow['jobs']['live-cli-smoke']['strategy']['matrix']['source'] == [
        'certspotter',
        'crtsh',
        'duckduckgo',
        'hackertarget',
        'otx',
        'rapiddns',
        'urlscan',
        'yahoo',
    ]

    provider_commands = '\n'.join(step.get('run', '') for step in workflow['jobs']['live-provider-tests']['steps'])
    cli_commands = '\n'.join(step.get('run', '') for step in workflow['jobs']['live-cli-smoke']['steps'])
    assert 'pytest --run-live-network -m live_network' in provider_commands
    assert 'ActivityClass.PASSIVE' in cli_commands
    assert '-l 10 -q' in cli_commands


def test_release_dependencies_are_reusable_workflows() -> None:
    for path in (CI_WORKFLOW_PATH, HARVESTVIEW_WORKFLOW_PATH, CONTAINER_WORKFLOW_PATH):
        assert 'workflow_call' in _workflow(path)['on']


def test_harvestview_browser_failures_keep_only_targeted_diagnostics() -> None:
    workflow = _workflow(HARVESTVIEW_WORKFLOW_PATH)
    steps = workflow['jobs']['harvestview-e2e']['steps']
    test_command = next(step['run'] for step in steps if step['name'] == 'Run HarvestView browser tests')
    upload = next(step for step in steps if step['name'] == 'Upload browser test artifacts')

    assert '--video' not in test_command
    assert '--tracing=retain-on-failure' in test_command
    assert '--screenshot=only-on-failure' in test_command
    assert upload['if'] == '${{ failure() }}'
