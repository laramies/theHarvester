import sys
import tomllib
from pathlib import Path

import pytest

from theHarvester import harvestview


def test_project_scripts_expose_commands() -> None:
    scripts = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))['project']['scripts']

    assert scripts == {
        'theHarvester': 'theHarvester.theHarvester:main',
        'harvestview': 'theHarvester.harvestview:main',
        'harvest-report': 'theHarvester.saved_run_report:main',
    }


def test_help_does_not_offer_rate_limit_configuration(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['harvestview', '--help'])

    with pytest.raises(SystemExit) as exit_info:
        harvestview.main()

    assert exit_info.value.code == 0
    assert '--rate-limit' not in capsys.readouterr().out
