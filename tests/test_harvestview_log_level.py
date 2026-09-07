import sys
from unittest.mock import Mock

import pytest

from theHarvester import harvestview


@pytest.mark.parametrize('option', ['-l', '--log-level'])
@pytest.mark.parametrize('value', ['nonsense', ''])
def test_invalid_log_level_is_rejected_before_server_start(monkeypatch, capsys, option, value):
    run = Mock()
    monkeypatch.setattr(harvestview.uvicorn, 'run', run)
    monkeypatch.setattr(sys, 'argv', ['harvestview', option, value])

    with pytest.raises(SystemExit) as exit_info:
        harvestview.main()

    assert exit_info.value.code == 2
    run.assert_not_called()
    error = capsys.readouterr().err
    assert 'invalid choice' in error
    assert 'warning' in error
    assert 'Traceback' not in error


@pytest.mark.parametrize('level', ['critical', 'error', 'warning', 'info', 'debug', 'trace'])
@pytest.mark.parametrize('uppercase', [False, True])
def test_valid_log_levels_remain_case_insensitive(monkeypatch, level, uppercase):
    run = Mock()
    monkeypatch.setattr(harvestview.uvicorn, 'run', run)
    monkeypatch.setattr(sys, 'argv', ['harvestview', '--log-level', level.upper() if uppercase else level])

    harvestview.main()

    run.assert_called_once()
    assert run.call_args.kwargs['log_level'] == level


def test_log_level_defaults_to_info(monkeypatch):
    run = Mock()
    monkeypatch.setattr(harvestview.uvicorn, 'run', run)
    monkeypatch.setattr(sys, 'argv', ['harvestview'])

    harvestview.main()

    run.assert_called_once()
    assert run.call_args.kwargs['log_level'] == 'info'
